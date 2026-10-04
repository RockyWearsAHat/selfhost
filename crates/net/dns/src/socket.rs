//! Port 53 sockets that a replacement server can share.
//!
//! A new resolver binds :53 beside the running one (`SO_REUSEADDR`, plus
//! `SO_REUSEPORT` on Unix), proves it answers, and only then does the old one
//! exit, so the port is never closed. Never `SO_EXCLUSIVEADDRUSE`: that is
//! exactly what would make the swap impossible.

use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

/// A UDP socket on `bind` that another instance may share.
pub fn bind_udp_shared(bind: SocketAddr) -> io::Result<UdpSocket> {
    let socket = shared(bind, socket2::Type::DGRAM)?;
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    ignore_connection_resets(&socket)?;
    Ok(socket)
}

/// A TCP listener on `bind` that another instance may share.
pub fn bind_tcp_shared(bind: SocketAddr) -> io::Result<TcpListener> {
    let socket = shared(bind, socket2::Type::STREAM)?;
    socket.bind(&bind.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

fn shared(bind: SocketAddr, kind: socket2::Type) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(bind), kind, None)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    Ok(socket)
}

/// Stops Windows reporting a client's closed port as an error on the next receive.
///
/// A reply to a client that already gave up draws an ICMP port-unreachable,
/// and Windows then fails the socket's next `recv_from` with WSAECONNRESET.
/// The serve loop survives that, but under load (exactly when clients give
/// up) it becomes a flood of receive errors that reads like an outage.
/// Elsewhere the kernel never reports it, so this does nothing.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn ignore_connection_resets(socket: &UdpSocket) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawSocket;

    /// `_WSAIOW(IOC_VENDOR, 12)`.
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            socket: usize,
            code: u32,
            in_buffer: *const c_void,
            in_length: u32,
            out_buffer: *mut c_void,
            out_length: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
            completion: *const c_void,
        ) -> i32;
    }

    let report_resets: u32 = 0; // BOOL FALSE
    let mut returned = 0_u32;
    // SAFETY: the socket is open for the whole call, the input is a 4-byte
    // BOOL that outlives it, and no output buffer or overlapped I/O is used.
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&raw const report_resets).cast(),
            4,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Elsewhere a closed client port never fails a receive.
#[cfg(not(windows))]
pub fn ignore_connection_resets(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_instance_binds_the_same_udp_and_tcp_port() {
        let first = bind_udp_shared("127.0.0.1:0".parse().unwrap()).expect("first udp");
        let port = first.local_addr().unwrap();
        let second = bind_udp_shared(port).expect("second udp on the same port");
        assert_eq!(second.local_addr().unwrap(), port);

        let first = bind_tcp_shared("127.0.0.1:0".parse().unwrap()).expect("first tcp");
        let port = first.local_addr().unwrap();
        let second = bind_tcp_shared(port).expect("second tcp on the same port");
        assert_eq!(second.local_addr().unwrap(), port);
    }
}
