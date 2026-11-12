//! In-memory test transport for testing.
//!
//! This module provides [`TestNetwork`] and [`TestTransport`] for testing
//! using in-memory channels instead of real network transports.

use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use iroh_base::{CustomAddr, EndpointId, TransportAddr};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::info;

use crate::{
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Item},
    endpoint::{
        Builder,
        presets::Preset,
        transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit},
    },
};

/// The transport ID used by [`TestNetwork`].
///
/// See `TRANSPORTS.md` for the registry of transport IDs.
pub const TEST_TRANSPORT_ID: u64 = 0x20;

/// An outgoing packet that can be sent across channels.
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub(crate) data: Bytes,
    pub(crate) from: CustomAddr,
}

/// A test transport for use with [`TestNetwork`].
///
/// Implements [`CustomTransport`] and [`CustomEndpoint`] for testing.
#[derive(Debug, Clone)]
pub struct TestTransport {
    id: EndpointId,
    id_watchable: n0_watcher::Watchable<Vec<CustomAddr>>,
    network: TestNetwork,
}

impl Preset for Arc<TestTransport> {
    /// Configures the builder with this transport and the network's address lookup.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let network = TestNetwork::new();
    /// let transport = network.create_transport(secret_key.public())?;
    /// let ep = Endpoint::builder()
    ///     .secret_key(secret_key)
    ///     .preset(transport)
    ///     .bind()
    ///     .await?;
    /// ```
    fn apply(self, builder: Builder) -> Builder {
        builder
            .add_custom_transport(self.clone())
            .address_lookup(self.network.address_lookup())
    }
}

/// A simulated network for testing custom transports.
///
/// This allows creating multiple [`TestTransport`] instances that can communicate
/// with each other through in-memory channels.
///
/// # Example
///
/// ```ignore
/// use iroh::test_utils::custom_transport::TestNetwork;
///
/// let network = TestNetwork::new();
/// let transport1 = network.create_transport(endpoint_id1)?;
/// let transport2 = network.create_transport(endpoint_id2)?;
/// // transport1 and transport2 can now communicate via the network
/// ```
#[derive(Debug, Clone, Default)]
pub struct TestNetwork {
    inner: Arc<Mutex<TestNetworkInner>>,
}

impl TestNetwork {
    /// Creates a new empty test network.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an address lookup service for this network.
    pub fn address_lookup(&self) -> impl AddressLookup {
        TestAddrLookup {
            network: self.clone(),
        }
    }

    /// Creates a new test transport for the given endpoint ID.
    ///
    /// Returns an error if the ID already exists in the network.
    pub fn create_transport(&self, id: EndpointId) -> io::Result<Arc<TestTransport>> {
        let id_custom = to_custom_addr(id);
        let mut guard = self.inner.lock().expect("poisoned");
        if guard.channels.contains_key(&id) {
            return Err(io::Error::other("endpoint ID already exists in network"));
        }
        guard.channels.insert(id, mpsc::channel(256));
        drop(guard);
        Ok(Arc::new(TestTransport {
            id_watchable: n0_watcher::Watchable::new(vec![id_custom]),
            network: self.clone(),
            id,
        }))
    }

    /// ember: from now on what is sent to `id` is lost on the way, as on a path that went dead without a word.
    pub fn black_hole(&self, id: EndpointId) {
        self.inner.lock().expect("poisoned").black_holes.insert(id);
    }

    /// ember: drops every packet sent while `dropping` (a transport that is not carrying yet, as Salix's socket
    /// before it is registered), or carries them again.
    pub fn set_dropping(&self, dropping: bool) {
        self.inner.lock().expect("poisoned").dropping = dropping;
    }

    /// ember: carries packets to `id` again after [`Self::black_hole`].
    pub fn mend(&self, id: EndpointId) {
        self.inner.lock().expect("poisoned").black_holes.remove(&id);
    }
}

#[derive(Debug)]
struct TestAddrLookup {
    network: TestNetwork,
}

#[derive(Debug, Default)]
struct TestNetworkInner {
    channels: BTreeMap<EndpointId, (mpsc::Sender<Packet>, mpsc::Receiver<Packet>)>,
    /// ember: endpoints whose packets are lost on the way (`TestNetwork::black_hole`).
    black_holes: std::collections::BTreeSet<EndpointId>,
    /// ember: every packet is lost (`TestNetwork::set_dropping`).
    dropping: bool,
}

impl AddressLookup for TestAddrLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_future::stream::Boxed<Result<Item, crate::address_lookup::Error>>> {
        if self
            .network
            .inner
            .lock()
            .expect("poisoned")
            .channels
            .contains_key(&endpoint_id)
        {
            Some(Box::pin(n0_future::stream::once(Ok(Item::new(
                EndpointInfo {
                    endpoint_id,
                    data: EndpointData::from_iter([TransportAddr::Custom(CustomAddr::from_parts(
                        TEST_TRANSPORT_ID,
                        endpoint_id.as_bytes(),
                    ))]),
                },
                "test discovery",
                None,
            )))))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
struct TestSender {
    id: EndpointId,
    network: TestNetwork,
}

/// Converts an endpoint ID to a custom address for this test transport.
pub fn to_custom_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from((TEST_TRANSPORT_ID, &endpoint.as_bytes()[..]))
}

fn try_parse_custom_addr(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != TEST_TRANSPORT_ID {
        return Err(io::Error::other("unexpected transport id"));
    }
    let key_bytes: &[u8; 32] = addr
        .data()
        .try_into()
        .map_err(|_| io::Error::other("wrong key length"))?;
    EndpointId::from_bytes(key_bytes).map_err(|_| io::Error::other("KeyParseError"))
}

impl TestSender {
    fn send_sync(&self, dst: &CustomAddr, packets: Vec<Packet>) -> io::Result<()> {
        let to_id = try_parse_custom_addr(dst)?;
        let guard = self.network.inner.lock().expect("poisoned");
        if guard.dropping || guard.black_holes.contains(&to_id) {
            return Ok(());
        }
        let (s, _) = guard
            .channels
            .get(&to_id)
            .ok_or_else(|| io::Error::other("Unknown endpoint"))?;
        for packet in packets {
            let len = packet.data.len();
            match s.try_send(packet) {
                Ok(_) => info!(
                    "send {} -> {}: sent {} bytes",
                    self.id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Full(_)) => info!(
                    "send {} -> {}: dropped {} bytes",
                    self.id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Closed(_)) => return Err(io::Error::other("channel closed")),
            }
        }
        Ok(())
    }

    fn split(&self, transmit: &Transmit) -> impl Iterator<Item = Packet> {
        let from = to_custom_addr(self.id);
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        transmit
            .contents
            .chunks(segment_size)
            .map(move |slice| Packet {
                from: from.clone(),
                data: Bytes::copy_from_slice(slice),
            })
    }
}

impl CustomSender for TestSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == TEST_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let packets = self.split(transmit).collect();
        Poll::Ready(self.send_sync(dst, packets))
    }
}

impl CustomTransport for TestTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        Ok(Box::new(self.clone()))
    }
}

impl CustomEndpoint for TestTransport {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.id_watchable.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(TestSender {
            id: self.id,
            network: self.network.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert_eq!(
            bufs.len(),
            recv_infos.len(),
            "non matching bufs & recv_infos"
        );
        let n = bufs.len();
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.network.inner.lock().expect("poisoned");
        let Some((_, r)) = guard.channels.get_mut(&self.id) else {
            info!("me: {} not found in channels", self.id.fmt_short());
            return Poll::Ready(Ok(0));
        };
        let mut packets = Vec::new();
        match r.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("channel closed"))),
            Poll::Ready(n) => n,
        };
        let mut count = 0;
        for (i, packet) in packets.into_iter().enumerate() {
            let meta = &mut metas[i];
            let buf = &mut bufs[i];
            let recv_info = &mut recv_infos[i];
            if buf.len() < packet.data.len() {
                break;
            }
            let from = try_parse_custom_addr(&packet.from).expect("valid custom addr");
            info!(
                "recv {} -> {}: copying {} bytes",
                from.fmt_short(),
                self.id.fmt_short(),
                packet.data.len()
            );
            buf[..packet.data.len()].copy_from_slice(&packet.data);
            *recv_info = RecvInfo::new(packet.from, Some(to_custom_addr(self.id)));
            meta.len = packet.data.len();
            meta.stride = packet.data.len();
            count += 1;
        }
        if count > 0 {
            info!("recv {}: filled {count} slots", self.id.fmt_short());
            Poll::Ready(Ok(count))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use iroh_relay::RelayMap;
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;

    use super::*;
    use crate::{
        Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
        endpoint::{Builder, Connection, presets, transports::AddrKind},
        protocol::{AcceptError, ProtocolHandler, Router},
        socket::biased_rtt_path_selector::{BiasedRttPathSelector, TransportBias},
        test_utils::run_relay_server,
    };

    const ECHO_ALPN: &[u8] = b"test/echo";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }

    /// Configuration for endpoint builder.
    #[derive(Clone, Default)]
    struct EndpointConfig {
        custom_bias: Option<TransportBias>,
        keep_ip: bool,
        relay_map: Option<RelayMap>,
        /// ember: a path given up 3 s after it goes quiet (heard every second), as the mesh of Comma's sets it.
        short_path_idle: bool,
    }

    impl EndpointConfig {
        fn with_custom_bias(mut self, bias: TransportBias) -> Self {
            self.custom_bias = Some(bias);
            self
        }

        fn with_ip(mut self) -> Self {
            self.keep_ip = true;
            self
        }

        fn with_relay(mut self, relay_map: RelayMap) -> Self {
            self.relay_map = Some(relay_map);
            self
        }

        fn with_short_path_idle(mut self) -> Self {
            self.short_path_idle = true;
            self
        }
    }

    /// Creates a basic endpoint builder with the given secret key and custom transport.
    fn endpoint_builder(
        secret_key: SecretKey,
        transport: Arc<TestTransport>,
        config: EndpointConfig,
    ) -> Builder {
        let relay_mode = match config.relay_map {
            Some(map) => RelayMode::Custom(map),
            None => RelayMode::Disabled,
        };
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .relay_mode(relay_mode)
            .ca_tls_config(crate::tls::CaTlsConfig::insecure_skip_verify())
            .add_custom_transport(transport);
        if let Some(bias) = config.custom_bias {
            builder = builder.path_selector(Arc::new(
                BiasedRttPathSelector::default()
                    .with_bias(AddrKind::Custom(TEST_TRANSPORT_ID), bias),
            ));
        }
        if !config.keep_ip {
            builder = builder.clear_ip_transports();
        }
        if config.short_path_idle {
            builder = builder.transport_config(
                crate::endpoint::QuicTransportConfig::builder()
                    .default_path_keep_alive_interval(Duration::from_secs(1))
                    .default_path_max_idle_timeout(Duration::from_secs(3))
                    .build(),
            );
        }
        builder
    }

    /// Creates an address with both IP (from endpoint) and custom transport addresses.
    fn mixed_addr(ep: &Endpoint, endpoint_id: EndpointId) -> EndpointAddr {
        let ep_addr = ep.addr();
        let custom_addr = to_custom_addr(endpoint_id);
        EndpointAddr::from_parts(
            endpoint_id,
            ep_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(custom_addr))),
        )
    }

    /// Creates an address with only the custom transport address.
    fn custom_only_addr(endpoint_id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(
            endpoint_id,
            std::iter::once(TransportAddr::Custom(to_custom_addr(endpoint_id))),
        )
    }

    /// Returns true if the selected path is the custom transport.
    fn is_custom_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths();
        paths.iter().find(|p| p.is_selected()).is_some_and(
            |p| matches!(p.remote_addr(), TransportAddr::Custom(a) if a.id() == TEST_TRANSPORT_ID),
        )
    }

    /// Returns true if either
    /// - we have both IP and custom paths, and the selected path is IP.
    /// - we only have one path
    fn is_ip_selected_from_ip_and_custom(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths();
        let has_ip = paths.iter().any(|p| p.remote_addr().is_ip());
        let has_custom = paths.iter().any(|p| p.remote_addr().is_custom());
        if !has_ip || !has_custom {
            return true;
        }
        paths
            .iter()
            .any(|p| p.is_selected() && p.remote_addr().is_ip())
    }

    /// Returns true if the selected path is a relay transport.
    fn is_relay_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths();
        paths
            .iter()
            .find(|p| p.is_selected())
            .is_some_and(|p| p.is_relay())
    }

    /// ember: waits until `settled` holds of `conn`'s paths, as they are chosen after the handshake. Not a deadline:
    /// a test asserts it afterwards, and 30 s only keeps a broken run from hanging. A fixed wait of 100-200 ms lost
    /// to a busy CI machine.
    async fn settle(conn: &crate::endpoint::Connection, settled: fn(&crate::endpoint::Connection) -> bool) {
        let _ = tokio::time::timeout(Duration::from_secs(30), async {
            while !settled(conn) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    /// Verifies echo works over the connection.
    async fn verify_echo(conn: &crate::endpoint::Connection, msg: &[u8]) -> Result<()> {
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(msg).await.anyerr()?;
        send.finish().anyerr()?;
        let response = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(response, msg);
        Ok(())
    }

    /// Test custom transport only - no IP, no relay, dial by custom address.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_only() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        let ep1 = endpoint_builder(s1, t1, EndpointConfig::default())
            .bind()
            .await?;
        let ep2 = endpoint_builder(s2.clone(), t2, EndpointConfig::default())
            .bind()
            .await?;
        let router = Router::builder(ep2).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(custom_only_addr(s2.public()), ECHO_ALPN)
            .await?;

        // Verify exactly one path exists and it's the custom transport
        let paths = conn.paths();
        assert_eq!(paths.len(), 1, "Expected exactly one path");
        assert!(
            is_custom_selected(&conn),
            "Custom transport should be selected"
        );

        verify_echo(&conn, b"custom only").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that custom transports can surface a local address per incoming packet.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_local_addr() -> Result<()> {
        use crate::endpoint::LocalTransportAddr;

        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        let ep1 = endpoint_builder(s1, t1, EndpointConfig::default())
            .bind()
            .await?;
        let ep2 = endpoint_builder(s2.clone(), t2, EndpointConfig::default())
            .alpns(vec![ECHO_ALPN.to_vec()])
            .bind()
            .await?;

        let connect = tokio::spawn({
            let ep1 = ep1.clone();
            let dst = custom_only_addr(s2.public());
            async move { ep1.connect(dst, ECHO_ALPN).await }
        });

        let incoming = ep2.accept().await.expect("incoming");
        assert_eq!(
            incoming.local_addr(),
            LocalTransportAddr::Custom(Some(to_custom_addr(s2.public()))),
        );
        let _conn = incoming.accept().anyerr()?.await.anyerr()?;

        connect.await.anyerr()??;
        Ok(())
    }

    /// Test that custom transport is selected over IP when given an RTT advantage.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_wins_over_ip() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Strong RTT advantage for custom transport
        let custom_bias = TransportBias::primary().with_rtt_advantage(Duration::from_secs(10));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;

        settle(&conn, is_custom_selected).await;

        assert!(
            is_custom_selected(&conn),
            "Custom transport should be selected with RTT advantage"
        );

        verify_echo(&conn, b"custom wins").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// ember: a connection whose first path is IP, made while the custom transport dropped every packet (Salix's
    /// socket before it is registered), opens a path through the custom transport once it carries packets, and
    /// selects it. Its first path was the only one it ever had over a custom transport before.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_path_opened_after_ip_won_the_handshake() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        let custom_bias = TransportBias::primary().with_rtt_advantage(Duration::from_secs(10));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        network.black_hole(s2.public());
        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;
        assert!(!is_custom_selected(&conn), "the custom transport carried nothing yet");

        network.mend(s2.public());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !is_custom_selected(&conn) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the custom path was never opened: {:?}",
                conn.paths()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        verify_echo(&conn, b"custom after ip").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Waits until `done` holds, at most `secs` seconds.
    async fn until(secs: u64, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while !done() {
            assert!(tokio::time::Instant::now() < deadline, "{what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// ember: the endpoints of a test of a custom transport that does not carry yet: IP and the custom transport, the
    /// custom one preferred, paths given up 3 s after they go quiet (as in Comma's mesh).
    async fn custom_later_endpoints(network: &TestNetwork) -> Result<(Endpoint, Endpoint, Router, SecretKey)> {
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();
        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;
        let custom_bias = TransportBias::primary().with_rtt_advantage(Duration::from_secs(10));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias)
            .with_short_path_idle();
        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();
        Ok((ep1, ep2, router, s2))
    }

    /// ember: a custom transport that never answers costs a connection 1 + `CUSTOM_PATH_TRIES` (5) path ids, however
    /// often it is asked to try (an address resolved again, another connection dialed), and dialing the remote again
    /// costs nothing more on a connection whose tries are over: the new connection has tries of its own.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_path_tries_bounded_per_connection() -> Result<()> {
        let network = TestNetwork::new();
        let (ep1, ep2, router, s2) = custom_later_endpoints(&network).await?;
        let addr = mixed_addr(&ep2, s2.public());

        network.set_dropping(true);
        let first = ep1.connect(addr.clone(), ECHO_ALPN).await?;
        // Asked again and again while it tries (each an address resolved).
        for _ in 0..40 {
            ep1.inner().anyerr()?.resolve_remote(addr.clone()).await.anyerr()?.anyerr()?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // A try lasts until its path is given up (3 s quiet, as in Comma's mesh), so six of them take about 20 s.
        until(60, "the first connection's tries were not over", || first.custom_path_tries() == 6).await;
        for dial in 1..=3 {
            let other = ep1.connect(addr.clone(), ECHO_ALPN).await?;
            until(60, "a later connection's tries were not over", || other.custom_path_tries() == 6).await;
            assert_eq!(first.custom_path_tries(), 6, "dial {dial} made the first connection try again");
            other.close(0u32.into(), b"done");
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(first.custom_path_tries(), 6, "the first connection tried again");

        verify_echo(&first, b"ip after the tries").await?;
        first.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// ember: a custom transport that starts to carry 1, 5 or 12 s after the dial (Salix's socket registered late), the
    /// remote's address resolved again every 100 ms meanwhile: the connection ends up on it each time. A try lasts until
    /// its path is given up (3 s quiet), so the later ones are made on new tries, which the resolves must not have used
    /// up. One that carries only after all the tries are over (about 20 s with the waits between tries a twentieth as
    /// long in tests; about a minute in a build) is not tried again until an event: a known limit.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_path_opened_when_the_transport_carries_late() -> Result<()> {
        for late_ms in [1_000u64, 5_000, 12_000] {
            let network = TestNetwork::new();
            let (ep1, ep2, router, s2) = custom_later_endpoints(&network).await?;
            let addr = mixed_addr(&ep2, s2.public());
            network.set_dropping(true);
            let conn = ep1.connect(addr.clone(), ECHO_ALPN).await?;
            let carries = tokio::time::Instant::now() + Duration::from_millis(late_ms);
            while tokio::time::Instant::now() < carries {
                ep1.inner().anyerr()?.resolve_remote(addr.clone()).await.anyerr()?.anyerr()?;
                tokio::time::sleep(Duration::from_millis(100).min(carries - tokio::time::Instant::now())).await;
            }
            network.set_dropping(false);
            until(15, &format!("not on the custom transport after it carried {late_ms} ms late: {:?}", conn.paths()), || {
                is_custom_selected(&conn)
            })
            .await;
            assert!(conn.custom_path_tries() <= 6, "{} tries", conn.custom_path_tries());
            verify_echo(&conn, b"custom late").await?;
            conn.close(0u32.into(), b"done");
            router.shutdown().await.anyerr()?;
        }
        Ok(())
    }

    /// ember: a connection whose tries to open a custom path are over (the custom transport dropped everything) is not
    /// tried again without an event, and is once the network changes (major): then the custom path opens and is
    /// selected.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_path_tried_again_on_a_major_network_change() -> Result<()> {
        let network = TestNetwork::new();
        let (ep1, ep2, router, s2) = custom_later_endpoints(&network).await?;
        network.set_dropping(true);
        let conn = ep1.connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN).await?;
        until(60, "the connection's tries were not over", || conn.custom_path_tries() == 6).await;
        // The last try is given up 3 s after it goes quiet.
        tokio::time::sleep(Duration::from_secs(4)).await;
        network.set_dropping(false);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!is_custom_selected(&conn), "tried again without an event: {:?}", conn.paths());

        ep1.inner().anyerr()?.force_network_change(true).await;
        until(10, &format!("the custom path was not tried again on the network change: {:?}", conn.paths()), || {
            is_custom_selected(&conn)
        })
        .await;
        verify_echo(&conn, b"custom after network change").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that IP is selected over custom transport when custom has an RTT disadvantage.
    #[tokio::test]
    #[traced_test]
    async fn test_ip_wins_over_custom() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Strong RTT disadvantage for custom transport
        let custom_bias = TransportBias::primary().with_rtt_disadvantage(Duration::from_secs(10));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;

        settle(&conn, is_ip_selected_from_ip_and_custom).await;

        assert!(
            is_ip_selected_from_ip_and_custom(&conn),
            "IP transport should be selected when custom has RTT disadvantage"
        );

        verify_echo(&conn, b"ip wins").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that custom transport (primary) is selected over relay (backup).
    ///
    /// This test first connects using only the relay address, then reconnects with
    /// both relay and custom addresses to verify the custom transport (primary) wins
    /// over the relay (backup).
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_wins_over_relay() -> Result<()> {
        let (relay_map, _relay_url, _guard) = run_relay_server().await?;
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Custom transport is primary by default, relay is backup
        let config = EndpointConfig::default().with_relay(relay_map.clone());

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;

        // Wait for relay connection to be established
        ep1.online().await;
        ep2.online().await;

        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        // Get all addresses including relay and custom
        let ep2_addr = ep2.addr();
        let custom_addr = to_custom_addr(s2.public());

        // Debug: print ep2 address to see what's available
        eprintln!("ep2 address: {:?}", ep2_addr);

        // Create address with both relay and custom
        let all_addrs = EndpointAddr::from_parts(
            s2.public(),
            ep2_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(custom_addr))),
        );
        eprintln!("Connecting with all addresses: {:?}", all_addrs);

        // First, connect with relay-only to verify relay works
        let relay_addrs: Vec<_> = ep2_addr
            .addrs
            .iter()
            .filter(|a| matches!(a, TransportAddr::Relay(_)))
            .cloned()
            .collect();
        eprintln!("Relay addresses in ep2_addr: {:?}", relay_addrs);

        // If there are no relay addresses, skip the relay-first test
        if relay_addrs.is_empty() {
            eprintln!(
                "WARNING: No relay addresses found in ep2_addr, skipping relay-first connection test"
            );
        } else {
            // Connect with relay-only address first to verify relay works
            let relay_only_addr = EndpointAddr::from_parts(s2.public(), relay_addrs.into_iter());
            eprintln!("Connecting with relay-only address: {:?}", relay_only_addr);

            let conn = ep1.connect(relay_only_addr, ECHO_ALPN).await?;

            settle(&conn, is_relay_selected).await;

            // Debug: print paths after relay-only connect
            let paths = conn.paths();
            eprintln!("Paths after relay-only connect:");
            for path in paths.iter() {
                eprintln!(
                    "  {} selected={} rtt={:?}",
                    path.remote_addr(),
                    path.is_selected(),
                    path.rtt()
                );
            }

            // Verify relay is currently selected
            assert!(
                is_relay_selected(&conn),
                "Relay should be selected after connecting with relay-only address"
            );

            verify_echo(&conn, b"relay test").await?;
            conn.close(0u32.into(), b"done with relay test");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Now connect with all addresses (relay + custom)
        let conn = ep1.connect(all_addrs, ECHO_ALPN).await?;

        settle(&conn, is_custom_selected).await;

        // Debug: print all paths
        let paths = conn.paths();
        eprintln!("Paths after connecting with all addresses:");
        for path in paths.iter() {
            eprintln!(
                "  {} selected={} rtt={:?}",
                path.remote_addr(),
                path.is_selected(),
                path.rtt()
            );
        }

        // Custom (primary) should win over relay (backup)
        assert!(
            is_custom_selected(&conn),
            "Custom transport (primary) should be selected over relay (backup)"
        );

        verify_echo(&conn, b"custom wins over relay").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// ember: a relay's front door, a TCP proxy the test slows and shuts: what goes through it waits `delay` ms
    /// either way; shut, it drops what runs through it and takes nothing new.
    struct RelayDoor {
        url: crate::RelayUrl,
        open: Arc<std::sync::atomic::AtomicBool>,
        running: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }

    impl RelayDoor {
        async fn to(relay: &crate::RelayUrl, delay: Duration) -> Result<Self> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.anyerr()?;
            let port = listener.local_addr().anyerr()?.port();
            let host = relay.host_str().expect("host").to_string();
            let target = format!("{host}:{}", relay.port().expect("port"));
            let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
            let (accepting, tasks) = (open.clone(), running.clone());
            tokio::spawn(async move {
                while let Ok((inbound, _)) = listener.accept().await {
                    if !accepting.load(std::sync::atomic::Ordering::SeqCst) {
                        continue;
                    }
                    let Ok(outbound) = tokio::net::TcpStream::connect(&target).await else {
                        continue;
                    };
                    let (down_read, down_write) = inbound.into_split();
                    let (up_read, up_write) = outbound.into_split();
                    let ways: [(
                        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    ); 2] = [
                        (Box::new(down_read), Box::new(up_write)),
                        (Box::new(up_read), Box::new(down_write)),
                    ];
                    for (mut from, mut to) in ways {
                        // A delay line: each read goes on `delay` after it came, in order.
                        let (tx, mut rx) =
                            tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
                        let mut held = tasks.lock().unwrap();
                        held.push(tokio::spawn(async move {
                            let mut buf = vec![0u8; 64 * 1024];
                            while let Ok(n) = from.read(&mut buf).await {
                                if n == 0
                                    || tx.send((tokio::time::Instant::now() + delay, buf[..n].to_vec())).is_err()
                                {
                                    break;
                                }
                            }
                        }));
                        held.push(tokio::spawn(async move {
                            while let Some((at, bytes)) = rx.recv().await {
                                tokio::time::sleep_until(at).await;
                                if to.write_all(&bytes).await.is_err() {
                                    break;
                                }
                            }
                        }));
                    }
                }
            });
            Ok(Self {
                url: format!("https://{host}:{port}").parse().expect("url"),
                open,
                running,
            })
        }

        fn shut(&self) {
            self.open.store(false, std::sync::atomic::Ordering::SeqCst);
            for task in self.running.lock().unwrap().drain(..) {
                task.abort();
            }
        }

        fn reopen(&self) {
            self.open.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// ember: two endpoints on a relay behind `door` and on `network`'s custom transport, no IP, and the server's
    /// address with both; the server echoes every stream.
    async fn relay_and_custom(
        network: &TestNetwork,
        door: &RelayDoor,
        custom_last: bool,
    ) -> Result<(Endpoint, Endpoint, EndpointAddr, tokio::task::JoinHandle<()>)> {
        const ALPN: &[u8] = b"ember/test/route";
        let bind = |secret: SecretKey| {
            let transport = network.create_transport(secret.public());
            let url = door.url.clone();
            async move {
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(secret)
                    .relay_mode(RelayMode::Custom(RelayMap::from_iter([url])))
                    .ca_tls_config(crate::tls::CaTlsConfig::insecure_skip_verify())
                    .add_custom_transport(transport.anyerr()?)
                    .clear_ip_transports()
                    .alpns(vec![ALPN.to_vec()]);
                let builder = if custom_last { builder.custom_transports_last() } else { builder };
                builder.bind().await.anyerr()
            }
        };
        let server = bind(SecretKey::generate()).await?;
        let client = bind(SecretKey::generate()).await?;
        server.online().await;
        let server_id = server.id();
        let addr = EndpointAddr::from_parts(
            server_id,
            [
                TransportAddr::Relay(door.url.clone()),
                TransportAddr::Custom(to_custom_addr(server_id)),
            ],
        );
        let accepting = tokio::spawn({
            let server = server.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    let Ok(conn) = incoming.await else { continue };
                    tokio::spawn(async move {
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            tokio::spawn(async move {
                                let _ = tokio::io::copy(&mut recv, &mut send).await;
                                let _ = send.finish();
                            });
                        }
                    });
                }
            }
        });
        Ok((server, client, addr, accepting))
    }

    fn selected(conn: &Connection) -> Option<TransportAddr> {
        conn.paths().iter().find(|p| p.is_selected()).map(|p| p.remote_addr().clone())
    }

    /// Echoes on `conn` until its selected path is `wanted`: a dead path is found by what it does not carry. The
    /// timeout only keeps a broken run from hanging.
    async fn until_selected(conn: &Connection, wanted: fn(&TransportAddr) -> bool) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !selected(conn).as_ref().is_some_and(wanted) {
                let _ = tokio::time::timeout(Duration::from_millis(300), verify_echo(conn, b"are you there")).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .anyerr()
    }

    /// ember: `custom_transports_last` carries a connection on the relay though the custom transport is faster; the
    /// relay lost, on the custom transport.
    #[tokio::test]
    async fn custom_transports_last_prefers_the_relay_and_falls_back() -> Result<()> {
        let (_map, relay_url, _relay_server) = run_relay_server().await?;
        let door = RelayDoor::to(&relay_url, Duration::from_millis(20)).await?;
        let network = TestNetwork::new();
        let (server, client, addr, accepting) = relay_and_custom(&network, &door, true).await?;
        let conn = client.connect(addr, b"ember/test/route").await.anyerr()?;

        until_selected(&conn, |a| matches!(a, TransportAddr::Relay(_))).await?;
        verify_echo(&conn, b"through the relay").await?;

        door.shut();
        until_selected(&conn, |a| matches!(a, TransportAddr::Custom(_))).await?;
        verify_echo(&conn, b"through the custom transport").await?;
        door.reopen();

        conn.close(0u32.into(), b"done");
        accepting.abort();
        client.close().await;
        server.close().await;
        Ok(())
    }

    /// ember: a new connection's handshake goes on every path while an older connection to the same peer has one
    /// selected. That path dead without a word (the peer's process restarted on another port), the older connection
    /// keeps it selected until it gives it up; the new one is made through the relay meanwhile.
    #[tokio::test]
    async fn a_new_connection_races_every_path_while_an_older_one_has_one_selected() -> Result<()> {
        let (_map, relay_url, _relay_server) = run_relay_server().await?;
        // The relay slower than the custom transport, which is selected then.
        let door = RelayDoor::to(&relay_url, Duration::from_millis(20)).await?;
        let network = TestNetwork::new();
        let (server, client, addr, accepting) = relay_and_custom(&network, &door, false).await?;
        let old = client.connect(addr.clone(), b"ember/test/route").await.anyerr()?;
        until_selected(&old, |a| matches!(a, TransportAddr::Custom(_))).await?;

        network.black_hole(server.id());
        let new = tokio::time::timeout(Duration::from_secs(60), client.connect(addr, b"ember/test/route"))
            .await
            .anyerr()?
            .anyerr()?;
        assert!(
            matches!(selected(&old), Some(TransportAddr::Custom(_))),
            "the new connection waited for the older one to give its dead path up: {:?}",
            selected(&old)
        );
        verify_echo(&new, b"through the relay").await?;

        new.close(0u32.into(), b"done");
        old.close(0u32.into(), b"done");
        accepting.abort();
        client.close().await;
        server.close().await;
        Ok(())
    }
}
