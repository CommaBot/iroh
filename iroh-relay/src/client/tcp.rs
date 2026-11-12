//! ember: compatibility for macOS guests on Apple's virtual network hardware. On affected paths every
//! multi-segment offloaded send is lost. Keep only this socket's unsent data below one segment; do not change
//! system settings or its flight window. Physical Macs and loopback connections retain Tokio's normal I/O.
//! Capping write() alone is insufficient: a closed congestion window coalesces queued writes.

//!
//! ember: and on every relay connection, what its socket has yet to send is kept small (UNSENT_MAX), so that what waits
//! to be written waits in the relay actor's queue, where it is dropped once too old (`MAX_SEND_WAIT`), not in the
//! socket's buffer (128 KB was seen), where it waits as long as a lossy line takes to send it (2026-11-12). The relay
//! server does the same for what it sends to a client (server/http_server.rs, NOTSENT_LOWAT).

/// ember: the most a relay connection's socket holds that it has not sent yet: a dozen datagrams.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
const UNSENT_MAX: u32 = 16 * 1024;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(super) use tokio::net::TcpStream;

/// ember: keeps what `stream` has yet to send to UNSENT_MAX (Linux and Android hold send() to it; Apple's are
/// bounded by their own `TcpStream`). A loopback connection (a local proxy, which owns its outward carrier) is left as
/// it is.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn bound_unsent(stream: &TcpStream) {
    if stream.peer_addr().is_ok_and(|addr| addr.ip().is_loopback()) {
        return;
    }
    if let Err(err) = socket2::SockRef::from(stream).set_tcp_notsent_lowat(UNSENT_MAX) {
        tracing::debug!("TCP_NOTSENT_LOWAT not set: {err}");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn bound_unsent(_stream: &TcpStream) {}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) use macos::TcpStream;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod macos {
    use std::{
        io::{self, IoSlice},
        net::SocketAddr,
        os::fd::AsRawFd,
        pin::Pin,
        sync::OnceLock,
        task::{Context, Poll, ready},
    };

    use socket2::SockRef;
    use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};

    // Public macOS <netinet/tcp.h>; libc does not currently expose this constant on Darwin.
    const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;

    #[derive(Debug)]
    pub(crate) struct TcpStream {
        inner: tokio::net::TcpStream,
        bounded: bool,
        /// ember: an Apple virtual Mac's: no more than one segment unsent (the offload loss above); else UNSENT_MAX.
        one_segment: bool,
    }

    fn virtual_mac() -> bool {
        static VIRTUAL_MAC: OnceLock<bool> = OnceLock::new();
        *VIRTUAL_MAC.get_or_init(|| {
            let mut model = [0u8; 128];
            let mut len = model.len();
            // Read-only, unprivileged hardware identity. Do not guess on an unknown/error response.
            // SAFETY: output is a live byte buffer; newp=null means this cannot change any setting.
            let rc = unsafe {
                libc::sysctlbyname(
                    c"hw.model".as_ptr(),
                    model.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            rc == 0 && len <= model.len() && model[..len].starts_with(b"VirtualMac")
        })
    }

    impl TcpStream {
        pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
            let inner = tokio::net::TcpStream::connect(addr).await?;
            // A local proxy owns its external TCP carrier; bounding our loopback hop cannot repair that.
            let loopback = match addr.ip() {
                std::net::IpAddr::V4(ip) => ip.is_loopback(),
                std::net::IpAddr::V6(ip) => {
                    ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
                }
            };
            Self::from_stream(inner, !loopback, !loopback && virtual_mac())
        }

        fn from_stream(inner: tokio::net::TcpStream, bounded: bool, one_segment: bool) -> io::Result<Self> {
            if !bounded {
                return Ok(Self { inner, bounded, one_segment });
            }
            inner.set_nodelay(true)?;
            // Public macOS <netinet/tcp.h>. Zero disables this option; one is its smallest enabled value.
            let lowat: libc::c_int = if one_segment { 1 } else { super::UNSENT_MAX as libc::c_int };
            // SAFETY: fd belongs to inner and the option points to one initialized c_int; nothing is retained.
            let rc = unsafe {
                libc::setsockopt(
                    inner.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    TCP_NOTSENT_LOWAT,
                    (&lowat as *const libc::c_int).cast(),
                    std::mem::size_of_val(&lowat) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { inner, bounded, one_segment })
        }

        pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
        pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.inner.peer_addr()
        }
        pub(crate) fn set_nodelay(&self, on: bool) -> io::Result<()> {
            self.inner.set_nodelay(on)
        }
    }

    impl AsRawFd for TcpStream {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.inner.as_raw_fd()
        }
    }

    impl AsyncRead for TcpStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.bounded {
                return Pin::new(&mut self.inner).poll_write(cx, buf);
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let inner = &self.inner;
            let one_segment = self.one_segment;
            loop {
                ready!(inner.poll_write_ready(cx))?;
                let result = inner.try_io(Interest::WRITABLE, || {
                    // Unlike Linux, macOS's NOTSENT_LOWAT gates readiness, not send(). Tokio caches readiness
                    // until WouldBlock, so recheck the OS before each send, even while its send buffer has room.
                    let mut fd = libc::pollfd {
                        fd: inner.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: one initialized pollfd, valid for the duration of this nonblocking poll.
                    let rc = unsafe { libc::poll(&mut fd, 1, 0) };
                    if rc < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if rc == 0 {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    let socket = SockRef::from(inner);
                    // Read the current MSS (a path MTU change can lower it). Readiness permits <= 1 unsent
                    // byte, so reserve that byte as well: the kernel never has more than one segment to emit.
                    // ember: elsewhere readiness permits UNSENT_MAX unsent, and one write adds at most that much.
                    let cap = if one_segment {
                        socket
                            .tcp_mss()?
                            .checked_sub(1)
                            .filter(|n| *n > 0)
                            .ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "invalid TCP MSS")
                            })? as usize
                    } else {
                        super::UNSENT_MAX as usize
                    };
                    socket.send(&buf[..buf.len().min(cap)])
                });
                match result {
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    other => return Poll::Ready(other),
                }
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            if !self.bounded {
                return Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
            }
            self.poll_write(
                cx,
                bufs.iter()
                    .find(|buf| !buf.is_empty())
                    .map_or(&[], |buf| &**buf),
            )
        }

        fn is_write_vectored(&self) -> bool {
            !self.bounded && self.inner.is_write_vectored()
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{future::poll_fn, io::IoSlice, time::Duration};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpSocket},
        };

        /// ember: a relay connection's socket keeps at most UNSENT_MAX unsent; an Apple virtual Mac's, one byte.
        #[tokio::test]
        async fn a_relay_connection_keeps_its_unsent_small() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            for (one_segment, want) in [(false, super::super::UNSENT_MAX as libc::c_int), (true, 1)] {
                let inner = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
                let sender = TcpStream::from_stream(inner, true, one_segment).unwrap();
                let mut lowat: libc::c_int = 0;
                let mut len = std::mem::size_of_val(&lowat) as libc::socklen_t;
                // SAFETY: reads one c_int option of a socket this test owns into a live c_int.
                let rc = unsafe {
                    libc::getsockopt(
                        sender.inner.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        TCP_NOTSENT_LOWAT,
                        (&mut lowat as *mut libc::c_int).cast(),
                        &mut len,
                    )
                };
                assert_eq!(rc, 0);
                assert_eq!(lowat, want);
            }
        }

        #[tokio::test]
        async fn loopback_keeps_native_vectored_io_and_large_writes() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut sender = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut receiver, _) = listener.accept().await.unwrap();
            assert!(!sender.bounded);
            assert!(sender.is_write_vectored());
            let mss = SockRef::from(&sender.inner).tcp_mss().unwrap() as usize;
            let data = vec![0x2a; 2 * mss];
            let n = sender.write(&data).await.unwrap();
            assert!(n > mss, "a loopback stream must retain normal batching");
            let mut received = vec![0; n];
            receiver.read_exact(&mut received).await.unwrap();
            assert_eq!(received, data[..n]);
        }

        // A small advertised receive window makes a reader that pauses exercise actual kernel backpressure.
        async fn pair() -> (TcpStream, tokio::net::TcpStream) {
            let listener = TcpSocket::new_v4().unwrap();
            listener.set_recv_buffer_size(4096).unwrap();
            listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let listener = listener.listen(1).unwrap();
            let sender = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let sender = TcpStream::from_stream(sender, true, true).unwrap();
            let (receiver, _) = listener.accept().await.unwrap();
            (sender, receiver)
        }

        #[tokio::test]
        async fn paused_reader_resumes_without_lost_bytes_or_large_queued_writes() {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (mut sender, mut receiver) = pair().await;
                let data: Vec<u8> = (0..512 * 1024).map(|n| (n % 251) as u8).collect();
                let mss = SockRef::from(&sender.inner).tcp_mss().unwrap() as usize;
                let mut offset = 0;
                // Establish write readiness once, then keep writing while the peer deliberately does not read.
                poll_fn(|cx| sender.inner.poll_write_ready(cx))
                    .await
                    .unwrap();
                poll_fn(|cx| {
                    loop {
                        match Pin::new(&mut sender).poll_write(cx, &data[offset..]) {
                            Poll::Pending => return Poll::Ready(()),
                            Poll::Ready(result) => {
                                let n = result.unwrap();
                                assert!(
                                    n > 0 && n < mss,
                                    "a write must not queue an offload-sized burst"
                                );
                                offset += n;
                                assert!(
                                    offset < data.len(),
                                    "the paused receiver must apply backpressure"
                                );
                            }
                        }
                    }
                })
                .await;
                assert!(offset > 0);
                assert_eq!(sender.write(&[]).await.unwrap(), 0);
                // Cancelling a pending write must not retain any bytes. Resume with exactly the unaccepted suffix.
                let ((), received) = tokio::join!(
                    async {
                        sender.write_all(&data[offset..]).await.unwrap();
                        sender.shutdown().await.unwrap();
                        let mut reply = [0; 3];
                        sender.read_exact(&mut reply).await.unwrap();
                        assert_eq!(&reply, b"ack");
                    },
                    async {
                        let mut received = Vec::new();
                        receiver.read_to_end(&mut received).await.unwrap();
                        receiver.write_all(b"ack").await.unwrap();
                        received
                    }
                );
                assert_eq!(received, data);
            })
            .await
            .expect("backpressure must wake the writer after the reader resumes");
        }

        #[tokio::test]
        async fn vectored_writes_preserve_bytes_and_segment_bound() {
            let (mut sender, mut receiver) = pair().await;
            let data = vec![0x5a; 128 * 1024];
            let mss = SockRef::from(&sender.inner).tcp_mss().unwrap() as usize;
            let bufs = [
                IoSlice::new(&[]),
                IoSlice::new(&data),
                IoSlice::new(b"tail"),
            ];
            let n = sender.write_vectored(&bufs).await.unwrap();
            assert!(n > 0 && n < mss);
            let ((), received) = tokio::join!(
                async {
                    sender.write_all(&data[n..]).await.unwrap();
                    sender.write_all(b"tail").await.unwrap();
                    sender.shutdown().await.unwrap();
                },
                async {
                    let mut received = Vec::new();
                    receiver.read_to_end(&mut received).await.unwrap();
                    received
                }
            );
            assert_eq!(received, [data.as_slice(), b"tail"].concat());
        }

        #[tokio::test]
        async fn reset_peer_reports_an_error_instead_of_waiting_for_writability() {
            tokio::time::timeout(Duration::from_secs(5), async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let sender = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let mut sender = TcpStream::from_stream(sender, true, true).unwrap();
                let (receiver, _) = listener.accept().await.unwrap();
                SockRef::from(&receiver)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(receiver);
                let read = sender.read(&mut [0; 1]).await;
                assert!(matches!(read, Ok(0) | Err(_)));
                assert!(sender.write_all(b"after reset").await.is_err());
            })
            .await
            .expect("a reset must not strand a writer waiting for readiness");
        }
    }
}
