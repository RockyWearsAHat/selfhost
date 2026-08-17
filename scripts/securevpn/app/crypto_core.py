"""
SecureVPN Cryptographic Core

Implements all cryptographic operations for the custom VPN protocol.
Uses modern, audited cryptographic primitives from the 'cryptography' library.
"""

import os
import struct
import time
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag


class CryptoException(Exception):
    """Base exception for cryptographic errors"""
    pass


class SecurityKeys:
    """Container for cryptographic keys used in a session"""
    
    def __init__(self, tx_key: bytes, rx_key: bytes):
        """
        Initialize security keys.
        
        Args:
            tx_key: 32-byte key for transmitting (encrypting outbound)
            rx_key: 32-byte key for receiving (decrypting inbound)
        """
        if len(tx_key) != 32 or len(rx_key) != 32:
            raise ValueError("Keys must be exactly 32 bytes")
        
        self.tx_cipher = ChaCha20Poly1305(tx_key)
        self.rx_cipher = ChaCha20Poly1305(rx_key)
        self.tx_counter = 0
        self.rx_counter = -1  # Start at -1 so first packet (counter 0) is accepted
        self.last_rekey = time.time()
        
        # Store raw keys for rekeying (will be zeroed on cleanup)
        self._tx_key = bytearray(tx_key)
        self._rx_key = bytearray(rx_key)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with counter-based nonce.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            [counter(8)] + [ciphertext + tag(16)]
        """
        # Check if rekey is needed (counter approaching limit)
        if self.tx_counter >= (2**64 - 1000):
            raise CryptoException("Counter exhaustion - rekey required")
        
        # 12-byte nonce: 4 bytes zeros + 8 bytes counter
        nonce = struct.pack('<I', 0) + struct.pack('<Q', self.tx_counter)
        
        # Encrypt with authentication
        ciphertext = self.tx_cipher.encrypt(nonce, plaintext, None)
        
        # Package: counter + ciphertext
        packet = struct.pack('<Q', self.tx_counter) + ciphertext
        self.tx_counter += 1
        
        return packet
    
    def decrypt(self, packet: bytes) -> bytes:
        """
        Decrypt and authenticate packet.
        
        Args:
            packet: [counter(8)] + [ciphertext + tag(16)]
            
        Returns:
            Decrypted plaintext
            
        Raises:
            CryptoException: On authentication failure or replay
        """
        if len(packet) < 24:  # 8 (counter) + 16 (tag minimum)
            raise CryptoException("Packet too short")
        
        # Extract counter and ciphertext
        counter = struct.unpack('<Q', packet[:8])[0]
        ciphertext = packet[8:]
        
        # Replay protection: counter must be greater than last received
        if counter <= self.rx_counter:
            raise CryptoException(f"Replay detected: counter {counter} <= {self.rx_counter}")
        
        # Check for suspicious counter jumps (possible attack or packet loss)
        if counter > self.rx_counter + 1000:
            raise CryptoException(f"Counter jump too large: {counter} vs {self.rx_counter}")
        
        # Reconstruct nonce
        nonce = struct.pack('<I', 0) + struct.pack('<Q', counter)
        
        try:
            # Decrypt and verify authentication tag
            plaintext = self.rx_cipher.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise CryptoException("Authentication failed - packet tampered")
        
        # Update counter only after successful decryption
        self.rx_counter = counter
        
        return plaintext
    
    def should_rekey(self, data_transferred: int = 0) -> bool:
        """
        Determine if rekeying is needed.
        
        Args:
            data_transferred: Bytes transferred in this session
            
        Returns:
            True if rekey should be performed
        """
        time_elapsed = time.time() - self.last_rekey
        
        # Rekey conditions
        return (
            time_elapsed > 3600 or  # 1 hour
            data_transferred > 1_000_000_000 or  # 1 GB
            self.tx_counter > (2**63)  # Counter halfway point
        )
    
    def __del__(self):
        """Zero out key material on deletion"""
        if hasattr(self, '_tx_key'):
            for i in range(len(self._tx_key)):
                self._tx_key[i] = 0
        if hasattr(self, '_rx_key'):
            for i in range(len(self._rx_key)):
                self._rx_key[i] = 0


class IdentityKeys:
    """Long-term identity keys for authentication"""
    
    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        """
        Initialize identity keys.
        
        Args:
            private_key: Existing Ed25519 private key, or None to generate new
        """
        if private_key is None:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self.private_key = private_key
        
        self.public_key = self.private_key.public_key()
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with identity key.
        
        Args:
            message: Data to sign
            
        Returns:
            64-byte signature
        """
        return self.private_key.sign(message)
    
    def get_public_bytes(self) -> bytes:
        """
        Get public key as raw 32 bytes.
        
        Returns:
            32-byte public key
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_private_bytes(self) -> bytes:
        """
        Get private key as raw 32 bytes (SENSITIVE).
        
        Returns:
            32-byte private key seed
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify an Ed25519 signature.
        
        Args:
            public_key_bytes: 32-byte public key
            message: Original message
            signature: 64-byte signature
            
        Returns:
            True if signature is valid
        """
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    
    @staticmethod
    def from_private_bytes(private_bytes: bytes) -> 'IdentityKeys':
        """
        Load identity from private key bytes.
        
        Args:
            private_bytes: 32-byte private key seed
            
        Returns:
            IdentityKeys instance
        """
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        return IdentityKeys(private_key)


class KeyExchange:
    """Ephemeral key exchange for session keys"""
    
    def __init__(self):
        """Generate ephemeral X25519 keypair"""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_secret: Optional[bytes] = None
    
    def get_public_bytes(self) -> bytes:
        """
        Get public key as raw 32 bytes.
        
        Returns:
            32-byte public key
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def derive_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """
        Perform ECDH to derive shared secret.
        
        Args:
            peer_public_bytes: Peer's 32-byte X25519 public key
            
        Returns:
            32-byte shared secret
            
        Raises:
            CryptoException: On invalid peer key
        """
        try:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            self.shared_secret = self.private_key.exchange(peer_public)
            return self.shared_secret
        except Exception as e:
            raise CryptoException(f"Key exchange failed: {e}")
    
    def derive_session_keys(self, shared_secret: bytes, is_client: bool) -> SecurityKeys:
        """
        Derive session keys from shared secret using HKDF.
        
        Args:
            shared_secret: 32-byte shared secret from ECDH
            is_client: True if this is the client side
            
        Returns:
            SecurityKeys with tx_key and rx_key
        """
        # Extract phase: derive master key from shared secret
        hkdf_extract = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureVPN-v1",
            backend=default_backend()
        )
        master_key = hkdf_extract.derive(shared_secret)
        
        # Expand phase: derive separate keys for each direction
        hkdf_tx = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=master_key,
            info=b"client-tx" if is_client else b"server-tx",
            backend=default_backend()
        )
        tx_key = hkdf_tx.derive(b"")
        
        hkdf_rx = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=master_key,
            info=b"server-tx" if is_client else b"client-tx",
            backend=default_backend()
        )
        rx_key = hkdf_rx.derive(b"")
        
        # Zero out master key from memory
        master_key = bytearray(master_key)
        for i in range(len(master_key)):
            master_key[i] = 0
        
        return SecurityKeys(tx_key, rx_key)
    
    def __del__(self):
        """Zero out shared secret on deletion"""
        if self.shared_secret is not None:
            secret = bytearray(self.shared_secret)
            for i in range(len(secret)):
                secret[i] = 0


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def secure_random(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes from OS CSPRNG
    """
    return os.urandom(length)


def validate_timestamp(timestamp: float, max_skew: float = 300.0) -> bool:
    """
    Validate that a timestamp is recent (within max_skew seconds).
    
    Args:
        timestamp: Unix timestamp to validate
        max_skew: Maximum allowed time difference in seconds
        
    Returns:
        True if timestamp is within acceptable range
    """
    current = time.time()
    diff = abs(current - timestamp)
    return diff <= max_skew
