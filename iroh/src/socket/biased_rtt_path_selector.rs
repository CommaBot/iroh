//! Default [`PathSelector`] implementation.
//!
//! [`BiasedRttPathSelector`] preserves iroh's historical "lowest biased RTT wins, with
//! stickiness against flapping" behaviour and is what's installed when no custom
//! selector is provided.

use std::{sync::Arc, time::Duration};

use rustc_hash::FxHashMap;
use tracing::trace;

use super::{
    remote_map::{PathSelection, PathSelectionContext, PathSelectionData, PathSelector},
    transports::AddrKind,
};
use crate::socket::transports::FourTuple;

/// How much do we prefer IPv6 over IPv4 by default.
const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// Stickiness threshold for biased RTT comparisons.  Switching to a same-tier path only
/// happens when its biased RTT is at least this much better than the current path's.
const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// ember: how much better a same-tier path's biased RTT must be for a switch to it: RTT_SWITCHING_MIN, or a quarter
/// of the current path's, whichever is more. Paths are chosen again as their RTTs change (remote_state.rs
/// PATH_RESELECT_INTERVAL), and two relays a few tens of milliseconds apart in jitter are not switched between each
/// time; one gone seconds slower than another is left.
fn switching_margin(current_biased: i128) -> i128 {
    (RTT_SWITCHING_MIN.as_nanos() as i128).max(current_biased / 4)
}

/// Bias configuration for a single transport kind.
///
/// Used by [`BiasedRttPathSelector`] to bias path selection per address kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TransportBias {
    /// RTT bias in nanoseconds.  Negative values make this transport more preferred.
    rtt_bias: i128,
}

impl TransportBias {
    /// Creates a primary transport bias with no RTT advantage.
    pub(crate) fn primary() -> Self {
        Self {
            rtt_bias: 0,
        }
    }

    /// Adds an RTT advantage to this transport, making it more preferred.
    pub(crate) fn with_rtt_advantage(mut self, advantage: Duration) -> Self {
        self.rtt_bias -= advantage.as_nanos() as i128;
        self
    }

    /// Adds an RTT disadvantage to this transport, making it less preferred.
    #[cfg(all(test, feature = "unstable-custom-transports"))]
    pub(crate) fn with_rtt_disadvantage(mut self, disadvantage: Duration) -> Self {
        self.rtt_bias += disadvantage.as_nanos() as i128;
        self
    }
}

/// The default [`PathSelector`] used by iroh.
///
/// Sorts paths by biased RTT. Switching only happens once a candidate is meaningfully
/// faster, avoiding flapping under jitter.
///
/// The biases are configured per [`AddrKind`].  Defaults: IPv4 and IPv6 are primary
/// (IPv6 has a 3ms RTT advantage); relay and custom transports have no advantage.
#[derive(Debug, Clone)]
pub(crate) struct BiasedRttPathSelector {
    biases: Arc<FxHashMap<AddrKind, TransportBias>>,
    /// ember: custom transports only while no other path has been measured (`Builder::custom_transports_last`).
    custom_last: bool,
}

impl Default for BiasedRttPathSelector {
    fn default() -> Self {
        let mut map = FxHashMap::default();
        map.insert(AddrKind::IpV4, TransportBias::primary());
        map.insert(
            AddrKind::IpV6,
            TransportBias::primary().with_rtt_advantage(IPV6_RTT_ADVANTAGE),
        );
        map.insert(AddrKind::Relay, TransportBias::primary());
        Self {
            biases: Arc::new(map),
            custom_last: false,
        }
    }
}

impl BiasedRttPathSelector {
    /// ember: direct paths and the relay first, by RTT; a custom transport only while none of them has been measured,
    /// however fast it is (`Builder::custom_transports_last`).
    pub(crate) fn custom_transports_last() -> Self {
        Self {
            custom_last: true,
            ..Self::default()
        }
    }

    /// Returns a new selector with the given bias added or updated for `kind`.
    #[cfg(all(test, feature = "unstable-custom-transports"))]
    pub(crate) fn with_bias(self, kind: AddrKind, bias: TransportBias) -> Self {
        let mut map = (*self.biases).clone();
        map.insert(kind, bias);
        Self {
            biases: Arc::new(map),
            custom_last: self.custom_last,
        }
    }

    /// Looks up the bias for an address.  Defaults to primary with no RTT bias.
    fn bias_for(&self, addr: &FourTuple) -> TransportBias {
        self.biases
            .get(&addr.addr_kind())
            .copied()
            .unwrap_or_else(TransportBias::primary)
    }

    /// Computes the sort key for a path: lower is better.
    fn sort_key(&self, addr: &FourTuple, rtt: Duration) -> i128 {
        let bias = self.bias_for(addr);
        (rtt.as_nanos() as i128).saturating_add(bias.rtt_bias)
    }
}

impl PathSelector for BiasedRttPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        // Single pass: track the best candidate by sort key, and the best (lowest)
        // sort key seen for the currently-selected address.  When the same address
        // appears multiple times (one path per connection), `min` over `sort_key`
        // naturally picks the lowest-RTT instance — no separate aggregation needed.
        let current = ctx.current();
        let mut best: Option<(PathSelectionData<'_>, i128)> = None;
        let mut current_key: Option<i128> = None;
        let mut current_seen = false;
        let mut first = None;
        // ember: with `custom_transports_last`, custom transports are left out once another path has an RTT.
        let is_custom = |path: &FourTuple| matches!(path.addr_kind(), AddrKind::Custom(_));
        let others = self.custom_last
            && ctx.paths().any(|psd| {
                !is_custom(psd.network_path())
                    && psd.stats().is_some_and(|stats| stats.same_path_rtt.is_some())
            });

        trace!("dumping path RTTs");
        for psd in ctx.paths() {
            let network_path = psd.network_path();
            if others && is_custom(network_path) {
                continue;
            }
            current_seen |= Some(network_path) == current;
            if first.is_none() {
                first = Some(psd.clone());
            }
            // Skip paths whose stats can't be read (e.g. closed concurrently with select).
            let Some(stats) = psd.stats() else {
                continue;
            };
            let Some(rtt) = stats.same_path_rtt else {
                continue;
            };
            trace!(%network_path, ?rtt);
            let key = self.sort_key(network_path, rtt);

            if Some(network_path) == current && current_key.is_none_or(|c| key < c) {
                current_key = Some(key);
            }
            if best.as_ref().is_none_or(|(_, b)| key < *b) {
                best = Some((psd, key));
            }
        }

        let mut selection = PathSelection::none();
        // A live current path with no comparable measurement must not be replaced by a guess.
        if current_seen && current_key.is_none() {
            return selection;
        }
        let Some((best_psd, best_biased)) = best else {
            // A connection still needs an initial path before any RTT can be measured.
            if !current_seen && let Some(first) = first {
                selection.set(&first);
            }
            return selection;
        };

        // If we have no current path or no data for it, switch to the best.
        let Some(current_biased) = current_key else {
            selection.set(&best_psd);
            return selection;
        };

        if best_biased + switching_margin(current_biased) <= current_biased {
            selection.set(&best_psd);
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use iroh_base::{EndpointId, RelayUrl};
    use noq::PathStats;

    use super::*;
    use crate::socket::{
        remote_map::{PathSelectionContext, PathSelectionData},
        transports::{self, Addr},
    };

    fn v4(port: u16) -> transports::FourTuple {
        transports::FourTuple::from_remote(Addr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))))
    }

    fn v6(port: u16) -> transports::FourTuple {
        transports::FourTuple::from_remote(Addr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            port,
            0,
            0,
        ))))
    }

    fn relay(port: u16) -> transports::FourTuple {
        let url = format!("https://relay{port}.iroh.computer")
            .parse::<RelayUrl>()
            .unwrap();
        transports::FourTuple::from_remote(Addr::Relay(
            url,
            EndpointId::from_bytes(&[0u8; 32]).unwrap(),
        ))
    }

    fn psd(addr: &transports::FourTuple, rtt_ms: u64) -> PathSelectionData<'_> {
        // PathStats is #[non_exhaustive], so build via Default + field assignment.
        let mut stats = PathStats::default();
        stats.rtt = Duration::from_millis(rtt_ms);
        stats.same_path_rtt = Some(stats.rtt);
        PathSelectionData::for_test(addr, Some(stats))
    }

    /// Runs [`BiasedRttPathSelector::default`] against the given paths and current
    /// selection, returning the selector's primary pick (cloned, for easier asserts).
    fn select_with_default(
        current: Option<&transports::FourTuple>,
        paths: Vec<PathSelectionData<'_>>,
    ) -> Option<transports::FourTuple> {
        let ctx = PathSelectionContext::for_test(current, paths);
        BiasedRttPathSelector::default()
            .select(&ctx)
            .selected()
            .cloned()
    }

    #[test]
    fn ipv6_wins_over_ipv4_within_bias() {
        let v4 = v4(1);
        let v6 = v6(1);

        // Equal RTTs: IPv6 wins because of the bias advantage.
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&v6, 10)]);
        assert_eq!(chosen.as_ref(), Some(&v6));

        // IPv6 still wins when 2ms slower (within the 3ms bias).
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&v6, 12)]);
        assert_eq!(chosen.as_ref(), Some(&v6));

        // IPv4 wins when IPv6 is 10ms slower (exceeds 3ms bias).
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&v6, 20)]);
        assert_eq!(chosen.as_ref(), Some(&v4));
    }

    #[test]
    fn faster_path_wins_across_ip_and_relay() {
        let v4 = v4(1);
        let relay = relay(1);

        let chosen = select_with_default(None, vec![psd(&v4, 100), psd(&relay, 10)]);
        assert_eq!(chosen.as_ref(), Some(&relay));
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&relay, 100)]);
        assert_eq!(chosen.as_ref(), Some(&v4));
    }

    #[test]
    fn slow_ip_yields_to_fast_relay() {
        let ip = v4(1);
        let relay = relay(1);
        // An IP route may itself go through an external tunnel or relay.
        let chosen = select_with_default(Some(&ip), vec![psd(&ip, 1000), psd(&relay, 50)]);
        assert_eq!(chosen.as_ref(), Some(&relay));
    }

    #[test]
    fn unknown_current_rtt_is_not_compared_to_a_known_path() {
        let ip = v4(1);
        let relay = relay(1);
        let unknown = PathSelectionData::for_test(&ip, Some(PathStats::default()));
        assert_eq!(select_with_default(Some(&ip), vec![unknown, psd(&relay, 10)]), None);
    }

    #[test]
    fn a_new_connection_can_start_without_rtt_samples() {
        let ip = v4(1);
        let unknown = PathSelectionData::for_test(&ip, Some(PathStats::default()));
        assert_eq!(select_with_default(None, vec![unknown]).as_ref(), Some(&ip));
    }

    #[test]
    fn same_tier_only_switches_with_significant_rtt_diff() {
        let v4_1 = v4(1);
        let v4_2 = v4(2);

        // 2ms diff < 5ms threshold → keep current (no switch, primary() == None).
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 18)]);
        assert_eq!(chosen, None);

        // 4ms diff < 5ms → keep current.
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 16)]);
        assert_eq!(chosen, None);

        // 5ms diff hits the threshold (the condition is `<=`) → switch.
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 15)]);
        assert_eq!(chosen.as_ref(), Some(&v4_2));

        // 6ms diff > 5ms → switch.
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 14)]);
        assert_eq!(chosen.as_ref(), Some(&v4_2));
    }

    #[test]
    fn same_tier_switches_by_a_quarter_of_a_slow_paths_rtt() {
        let a = relay(1);
        let b = relay(2);

        // 300ms against 260ms: within a quarter of the current, kept.
        let chosen = select_with_default(Some(&a), vec![psd(&a, 300), psd(&b, 260)]);
        assert_eq!(chosen, None);

        // 300ms against 200ms: switched.
        let chosen = select_with_default(Some(&a), vec![psd(&a, 300), psd(&b, 200)]);
        assert_eq!(chosen.as_ref(), Some(&b));

        // A relay gone 11.9s slow (2026-10-30) against one at 255ms: switched.
        let chosen = select_with_default(Some(&a), vec![psd(&a, 11_900), psd(&b, 255)]);
        assert_eq!(chosen.as_ref(), Some(&b));
    }

    #[test]
    fn no_current_path_selects_best() {
        let v4_1 = v4(1);
        let v4_2 = v4(2);
        let chosen = select_with_default(None, vec![psd(&v4_1, 20), psd(&v4_2, 10)]);
        assert_eq!(chosen.as_ref(), Some(&v4_2));
    }

    fn custom(id: u64) -> transports::FourTuple {
        transports::FourTuple::from_remote(Addr::Custom(iroh_base::CustomAddr::from_parts(id, &[1u8; 32])))
    }

    /// ember: `custom_transports_last` takes a custom transport only while no other path has an RTT: the relay
    /// however much slower, and the custom transport again once the relay has none.
    #[test]
    fn custom_transports_last_only_without_another_path() {
        let custom = custom(7);
        let relay = relay(1);
        let select = |current: Option<&transports::FourTuple>, paths| {
            let ctx = PathSelectionContext::for_test(current, paths);
            BiasedRttPathSelector::custom_transports_last()
                .select(&ctx)
                .selected()
                .cloned()
        };

        // Only the custom transport measured: it is taken.
        assert_eq!(select(None, vec![psd(&custom, 1)]).as_ref(), Some(&custom));
        // The relay measured, fifty times slower: the relay, and from the custom transport too.
        assert_eq!(select(None, vec![psd(&custom, 1), psd(&relay, 50)]).as_ref(), Some(&relay));
        assert_eq!(
            select(Some(&custom), vec![psd(&custom, 1), psd(&relay, 50)]).as_ref(),
            Some(&relay)
        );
        // The relay's path gone: the custom transport.
        assert_eq!(select(Some(&relay), vec![psd(&custom, 1)]).as_ref(), Some(&custom));

        // By default the faster wins.
        assert_eq!(
            select_with_default(None, vec![psd(&custom, 1), psd(&relay, 50)]).as_ref(),
            Some(&custom)
        );
    }

    #[test]
    fn empty_paths_returns_none() {
        // No current, no candidates: nothing to pick.
        assert_eq!(select_with_default(None, vec![]), None);

        // Current is set but there are no candidates: keep current (primary() == None).
        let v4 = v4(1);
        assert_eq!(select_with_default(Some(&v4), vec![]), None);
    }
}
