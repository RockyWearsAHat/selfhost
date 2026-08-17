"""
Key Management System

Handles generation, storage, and loading of cryptographic keys.
Keys are stored in a secure format with proper file permissions.
"""

import os
import json
import base64
from pathlib import Path
from typing import Optional

from crypto_core import IdentityKeys, CryptoException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


class KeyManager:
    """
    Manages identity keys with optional password protection.
    """
    
    DEFAULT_KEY_DIR = Path.home() / ".securevpn" / "keys"
    
    def __init__(self, key_dir: Optional[Path] = None):
        """
        Initialize key manager.
        
        Args:
            key_dir: Directory for key storage (default: ~/.securevpn/keys)
        """
        self.key_dir = key_dir or self.DEFAULT_KEY_DIR
        self.key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    
    def generate_identity(self, name: str, password: Optional[str] = None) -> IdentityKeys:
        """
        Generate a new identity keypair.
        
        Args:
            name: Identifier for this identity (e.g., "server", "client1")
            password: Optional password to encrypt private key
            
        Returns:
            New IdentityKeys
        """
        identity = IdentityKeys()
        self.save_identity(name, identity, password)
        return identity
    
    def save_identity(self, name: str, identity: IdentityKeys, password: Optional[str] = None):
        """
        Save identity keys to disk.
        
        Args:
            name: Identifier for this identity
            identity: IdentityKeys to save
            password: Optional password to encrypt private key
        """
        key_file = self.key_dir / f"{name}.key"
        pub_file = self.key_dir / f"{name}.pub"
        
        # Save public key (unencrypted)
        pub_bytes = identity.get_public_bytes()
        pub_b64 = base64.b64encode(pub_bytes).decode('ascii')
        
        pub_file.write_text(f"securevpn-ed25519 {pub_b64} {name}\n")
        pub_file.chmod(0o644)
        
        # Save private key
        priv_bytes = identity.get_private_bytes()
        
        if password:
            # Encrypt private key with password
            encrypted = self._encrypt_key(priv_bytes, password)
            key_data = {
                'type': 'encrypted',
                'algorithm': 'ed25519',
                'kdf': 'scrypt',
                'data': base64.b64encode(encrypted['ciphertext']).decode('ascii'),
                'salt': base64.b64encode(encrypted['salt']).decode('ascii'),
                'nonce': base64.b64encode(encrypted['nonce']).decode('ascii')
            }
        else:
            # Store unencrypted (WARNING: less secure)
            key_data = {
                'type': 'plain',
                'algorithm': 'ed25519',
                'data': base64.b64encode(priv_bytes).decode('ascii')
            }
        
        key_file.write_text(json.dumps(key_data, indent=2) + '\n')
        key_file.chmod(0o600)
        
        print(f"✓ Identity '{name}' saved to {self.key_dir}")
        print(f"  Private key: {key_file.name}")
        print(f"  Public key: {pub_file.name}")
    
    def load_identity(self, name: str, password: Optional[str] = None) -> IdentityKeys:
        """
        Load identity keys from disk.
        
        Args:
            name: Identifier for the identity
            password: Password if private key is encrypted
            
        Returns:
            Loaded IdentityKeys
            
        Raises:
            FileNotFoundError: If key file doesn't exist
            CryptoException: If decryption fails
        """
        key_file = self.key_dir / f"{name}.key"
        
        if not key_file.exists():
            raise FileNotFoundError(f"Identity '{name}' not found in {self.key_dir}")
        
        # Load key data
        key_data = json.loads(key_file.read_text())
        
        if key_data['algorithm'] != 'ed25519':
            raise CryptoException(f"Unsupported algorithm: {key_data['algorithm']}")
        
        # Decrypt/decode private key
        if key_data['type'] == 'encrypted':
            if password is None:
                raise CryptoException("Password required for encrypted key")
            
            ciphertext = base64.b64decode(key_data['data'])
            salt = base64.b64decode(key_data['salt'])
            nonce = base64.b64decode(key_data['nonce'])
            
            priv_bytes = self._decrypt_key(ciphertext, password, salt, nonce)
        elif key_data['type'] == 'plain':
            priv_bytes = base64.b64decode(key_data['data'])
        else:
            raise CryptoException(f"Unknown key type: {key_data['type']}")
        
        return IdentityKeys.from_private_bytes(priv_bytes)
    
    def load_peer_public_key(self, name: str) -> bytes:
        """
        Load peer's public key.
        
        Args:
            name: Identifier for the peer
            
        Returns:
            32-byte public key
            
        Raises:
            FileNotFoundError: If public key file doesn't exist
        """
        pub_file = self.key_dir / f"{name}.pub"
        
        if not pub_file.exists():
            raise FileNotFoundError(f"Public key '{name}.pub' not found in {self.key_dir}")
        
        # Parse public key file
        content = pub_file.read_text().strip()
        parts = content.split()
        
        if len(parts) < 2 or parts[0] != 'securevpn-ed25519':
            raise ValueError(f"Invalid public key format in {pub_file}")
        
        pub_bytes = base64.b64decode(parts[1])
        
        if len(pub_bytes) != 32:
            raise ValueError(f"Invalid public key length: {len(pub_bytes)}")
        
        return pub_bytes
    
    def import_peer_public_key(self, name: str, public_key_b64: str):
        """
        Import a peer's public key.
        
        Args:
            name: Identifier for the peer
            public_key_b64: Base64-encoded public key
        """
        pub_file = self.key_dir / f"{name}.pub"
        pub_file.write_text(f"securevpn-ed25519 {public_key_b64} {name}\n")
        pub_file.chmod(0o644)
        print(f"✓ Peer public key '{name}' imported to {pub_file}")
    
    def export_public_key(self, name: str) -> str:
        """
        Export public key as base64 string.
        
        Args:
            name: Identifier for the identity
            
        Returns:
            Base64-encoded public key
        """
        pub_file = self.key_dir / f"{name}.pub"
        
        if not pub_file.exists():
            raise FileNotFoundError(f"Public key '{name}.pub' not found")
        
        content = pub_file.read_text().strip()
        parts = content.split()
        
        if len(parts) < 2:
            raise ValueError("Invalid public key file format")
        
        return parts[1]
    
    def list_identities(self) -> list:
        """
        List all identities in key directory.
        
        Returns:
            List of identity names
        """
        identities = []
        for key_file in self.key_dir.glob("*.key"):
            identities.append(key_file.stem)
        return sorted(identities)
    
    def list_peers(self) -> list:
        """
        List all peer public keys.
        
        Returns:
            List of peer names
        """
        peers = []
        for pub_file in self.key_dir.glob("*.pub"):
            # Exclude our own public keys (those with corresponding .key files)
            if not (self.key_dir / f"{pub_file.stem}.key").exists():
                peers.append(pub_file.stem)
        return sorted(peers)
    
    @staticmethod
    def _encrypt_key(plaintext: bytes, password: str) -> dict:
        """
        Encrypt key material with password using Scrypt + ChaCha20-Poly1305.
        
        Args:
            plaintext: Key bytes to encrypt
            password: Password
            
        Returns:
            Dict with ciphertext, salt, and nonce
        """
        # Generate random salt
        salt = os.urandom(32)
        
        # Derive encryption key from password using Scrypt
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**18,  # CPU/memory cost
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        # Zero out derived key
        key = bytearray(key)
        for i in range(len(key)):
            key[i] = 0
        
        return {
            'ciphertext': ciphertext,
            'salt': salt,
            'nonce': nonce
        }
    
    @staticmethod
    def _decrypt_key(ciphertext: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
        """
        Decrypt key material with password.
        
        Args:
            ciphertext: Encrypted key
            password: Password
            salt: Salt used in KDF
            nonce: Nonce used in encryption
            
        Returns:
            Decrypted key bytes
            
        Raises:
            CryptoException: On wrong password or corruption
        """
        # Derive encryption key from password
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**18,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Decrypt
        cipher = ChaCha20Poly1305(key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise CryptoException(f"Decryption failed (wrong password?): {e}")
        finally:
            # Zero out derived key
            key = bytearray(key)
            for i in range(len(key)):
                key[i] = 0
        
        return plaintext


def setup_keys_interactive():
    """
    Interactive key setup for first-time users.
    """
    print("=== SecureVPN Key Setup ===\n")
    
    km = KeyManager()
    
    print("This will generate identity keys for server and client.")
    print(f"Keys will be stored in: {km.key_dir}\n")
    
    # Generate server identity
    print("Generating server identity...")
    server_password = input("Enter password to protect server key (or press Enter for none): ").strip()
    server_password = server_password if server_password else None
    
    server_identity = km.generate_identity("server", server_password)
    print()
    
    # Generate client identity
    print("Generating client identity...")
    client_password = input("Enter password to protect client key (or press Enter for none): ").strip()
    client_password = client_password if client_password else None
    
    client_identity = km.generate_identity("client", client_password)
    print()
    
    # Export keys for exchange
    print("=== Key Exchange ===")
    print("\nTo set up the VPN, you need to exchange public keys:")
    print(f"\n1. Server public key (share this with the client):")
    print(f"   {km.export_public_key('server')}")
    print(f"\n2. Client public key (share this with the server):")
    print(f"   {km.export_public_key('client')}")
    print("\n✓ Setup complete!")


if __name__ == "__main__":
    setup_keys_interactive()
