"""
SecureVPN Client

Connects to VPN server and exposes local port for SSH connections.
"""

import asyncio
import os
import signal
import sys
from typing import Optional

from crypto_core import IdentityKeys, SecurityKeys, CryptoException
from protocol import SecureVPNProtocol, ProtocolError, frame_packet, parse_framed_packet
from key_manager import KeyManager
from config import load_env


class VPNClient:
    """
    VPN client that connects to server and exposes local SSH port.
    """
    
    def __init__(
        self,
        identity: IdentityKeys,
        peer_public_key: bytes,
        server_host: str,
        server_port: int = 8443,
        local_host: str = "127.0.0.1",
        local_port: int = 2222
    ):
        """
        Initialize VPN client.
        
        Args:
            identity: Client identity keys
            peer_public_key: Server's public key (32 bytes)
            server_host: VPN server host
            server_port: VPN server port
            local_host: Local host to expose SSH proxy
            local_port: Local port to expose SSH proxy
        """
        self.identity = identity
        self.peer_public_key = peer_public_key
        self.server_host = server_host
        self.server_port = server_port
        self.local_host = local_host
        self.local_port = local_port
        self.session_keys: Optional[SecurityKeys] = None
        self.vpn_reader: Optional[asyncio.StreamReader] = None
        self.vpn_writer: Optional[asyncio.StreamWriter] = None
        self.local_server: Optional[asyncio.Server] = None
    
    async def connect(self):
        """Verify the server is reachable and authentic, then serve locally.

        Each local connection opens its OWN VPN session on demand (see
        ``handle_local_connection``) rather than sharing one tunnel. A single
        shared tunnel can only carry one stream — every parallel browser
        connection would interleave into one target socket and corrupt it. A
        session per local connection maps cleanly onto the server, which already
        tunnels each VPN connection to its own target socket. This preflight
        does one handshake up front so an authentication or reachability problem
        surfaces immediately instead of on the first request.
        """
        print(f"Connecting to VPN server at {self.server_host}:{self.server_port}...")

        try:
            reader, writer = await asyncio.open_connection(self.server_host, self.server_port)
            session_keys = await self.perform_handshake(reader, writer)
            if session_keys is None:
                raise ProtocolError("Handshake failed")
            # Preflight only: close it, real traffic gets fresh sessions.
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            print("✓ Handshake complete, server authenticated, secure tunnel ready")

            await self.start_local_proxy()

        except Exception as e:
            print(f"Connection failed: {e}")
            raise

    async def _open_session(self):
        """Open one VPN connection and complete the handshake.

        Returns ``(vpn_reader, vpn_writer, session_keys)`` or raises. Callers own
        the returned writer and must close it when the tunnel ends.
        """
        vpn_reader, vpn_writer = await asyncio.open_connection(self.server_host, self.server_port)
        session_keys = await self.perform_handshake(vpn_reader, vpn_writer)
        if session_keys is None:
            vpn_writer.close()
            raise ProtocolError("Handshake failed")
        return vpn_reader, vpn_writer, session_keys

    async def perform_handshake(
        self,
        vpn_reader: asyncio.StreamReader,
        vpn_writer: asyncio.StreamWriter,
    ) -> Optional[SecurityKeys]:
        """
        Perform client-side handshake over the given connection.

        Returns:
            SecurityKeys on success, None on failure
        """
        protocol = SecureVPNProtocol(self.identity, self.peer_public_key)
        buffer = b""

        try:
            # Step 1: Send CLIENT_HELLO
            client_hello, state = protocol.create_client_hello()
            vpn_writer.write(frame_packet(client_hello))
            await vpn_writer.drain()

            # Step 2: Receive SERVER_HELLO
            while True:
                data = await asyncio.wait_for(vpn_reader.read(4096), timeout=30.0)
                if not data:
                    raise ProtocolError("Connection closed during handshake")

                buffer += data
                packet, buffer = parse_framed_packet(buffer)

                if packet:
                    break

            # Process SERVER_HELLO
            session_keys = protocol.process_server_hello(packet, state)

            # Step 3: Send CLIENT_AUTH
            client_auth = protocol.create_client_auth(state, session_keys)
            vpn_writer.write(frame_packet(client_auth))
            await vpn_writer.drain()

            return session_keys

        except asyncio.TimeoutError:
            print("Handshake timeout")
            return None
        except (ProtocolError, CryptoException) as e:
            print(f"Handshake error: {e}")
            return None

    async def start_local_proxy(self):
        """Start local SSH proxy server."""
        self.local_server = await asyncio.start_server(
            self.handle_local_connection,
            self.local_host,
            self.local_port
        )
        
        print(f"\n✓ Local SSH proxy listening on {self.local_host}:{self.local_port}")
        print(f"✓ Connect with: ssh -p {self.local_port} user@{self.local_host}")
        print("✓ VPN tunnel active\n")
        
        async with self.local_server:
            await self.local_server.serve_forever()
    
    async def handle_local_connection(
        self,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter
    ):
        """
        Handle local SSH connection and tunnel through VPN.
        """
        client_addr = local_writer.get_extra_info('peername')
        conn_id = f"{client_addr[0]}:{client_addr[1]}"

        print(f"[{conn_id}] New local connection")

        # Each local connection gets its OWN authenticated VPN session and its
        # own target socket on the server. This is what lets a browser open many
        # parallel connections without their bytes interleaving in one tunnel.
        try:
            vpn_reader, vpn_writer, session_keys = await self._open_session()
        except Exception as e:
            print(f"[{conn_id}] Could not open VPN session: {e}")
            try:
                local_writer.close()
            except Exception:
                pass
            return

        protocol = SecureVPNProtocol(self.identity, self.peer_public_key)
        vpn_buffer = b""
        bytes_tx = 0
        bytes_rx = 0

        try:
            async def local_to_vpn():
                """Forward local SSH traffic to encrypted VPN"""
                nonlocal bytes_tx
                
                try:
                    while True:
                        data = await local_reader.read(8192)
                        if not data:
                            break
                        
                        # Encrypt and send through VPN
                        encrypted = protocol.create_data_packet(data, session_keys)
                        framed = frame_packet(encrypted)
                        bytes_tx += len(data)
                        
                        vpn_writer.write(framed)
                        await vpn_writer.drain()
                
                except Exception as e:
                    print(f"[{conn_id}] Local->VPN error: {e}")
                finally:
                    # Send close signal if needed
                    pass
            
            async def vpn_to_local():
                """Forward decrypted VPN traffic to local SSH"""
                nonlocal vpn_buffer, bytes_rx
                
                try:
                    while True:
                        data = await vpn_reader.read(8192)
                        if not data:
                            break
                        
                        vpn_buffer += data
                        
                        # Process all complete packets
                        while True:
                            packet, vpn_buffer = parse_framed_packet(vpn_buffer)
                            if packet is None:
                                break
                            
                            # Decrypt packet
                            payload = protocol.parse_data_packet(packet, session_keys)
                            bytes_rx += len(payload)
                            
                            # Forward to local SSH client
                            local_writer.write(payload)
                            await local_writer.drain()
                
                except Exception as e:
                    print(f"[{conn_id}] VPN->Local error: {e}")
                finally:
                    local_writer.close()
            
            # Run both directions concurrently
            await asyncio.gather(local_to_vpn(), vpn_to_local(), return_exceptions=True)
        
        except Exception as e:
            print(f"[{conn_id}] Error: {e}")
        finally:
            # Tear down this connection's own VPN session and local socket.
            try:
                vpn_writer.close()
            except Exception:
                pass
            try:
                local_writer.close()
                await local_writer.wait_closed()
            except Exception:
                pass
            print(f"[{conn_id}] Connection closed (TX: {bytes_tx} bytes, RX: {bytes_rx} bytes)")
    
    async def disconnect(self):
        """Disconnect from VPN server."""
        if self.vpn_writer:
            try:
                self.vpn_writer.close()
                await self.vpn_writer.wait_closed()
            except:
                pass
        
        if self.local_server:
            self.local_server.close()
            await self.local_server.wait_closed()


async def main():
    """Main client entry point"""
    import argparse
    
    load_env()

    parser = argparse.ArgumentParser(description="SecureVPN Client")
    parser.add_argument("server", nargs="?", default=os.getenv("SECUREVPN_CLIENT_SERVER_HOST"), help="VPN server host")
    parser.add_argument("--port", type=int, default=int(os.getenv("SECUREVPN_CLIENT_SERVER_PORT", "8443")), help="VPN server port (default: 8443)")
    parser.add_argument("--local-host", default=os.getenv("SECUREVPN_CLIENT_LOCAL_HOST", "127.0.0.1"), help="Local proxy host (default: 127.0.0.1)")
    parser.add_argument("--local-port", type=int, default=int(os.getenv("SECUREVPN_CLIENT_LOCAL_PORT", "2222")), help="Local proxy port (default: 2222)")
    parser.add_argument("--identity", default=os.getenv("SECUREVPN_CLIENT_IDENTITY", "client"), help="Identity name (default: client)")
    parser.add_argument("--peer", default=os.getenv("SECUREVPN_CLIENT_PEER", "server"), help="Peer name (default: server)")
    parser.add_argument("--password", help="Password for encrypted identity key")
    parser.add_argument("--key-dir", default=os.getenv("SECUREVPN_KEY_DIR"),
                        help="Directory holding identity/peer keys (default: ~/.securevpn/keys)")
    args = parser.parse_args()

    if not args.server:
        parser.error("VPN server host must be provided via CLI or SECUREVPN_CLIENT_SERVER_HOST")

    if not args.password:
        args.password = os.getenv("SECUREVPN_CLIENT_PASSWORD")
    
    # Load keys
    from pathlib import Path as _Path
    km = KeyManager(_Path(args.key_dir)) if args.key_dir else KeyManager()
    
    try:
        print("Loading client identity...")
        identity = km.load_identity(args.identity, args.password)
        print("✓ Client identity loaded")
        
        print("Loading server public key...")
        peer_pubkey = km.load_peer_public_key(args.peer)
        print("✓ Server public key loaded\n")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nRun key_manager.py first to generate keys.")
        sys.exit(1)
    except CryptoException as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Start client
    client = VPNClient(
        identity=identity,
        peer_public_key=peer_pubkey,
        server_host=args.server,
        server_port=args.port,
        local_host=args.local_host,
        local_port=args.local_port
    )
    
    # Handle graceful shutdown
    try:
        await client.connect()
    except KeyboardInterrupt:
        print("\n\n⚠ Shutting down client...")
        await client.disconnect()
        print("✓ Client stopped")
    except Exception as e:
        print(f"Client error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
