//! ember: the relays each remote may be reached through ([`crate::Endpoint::set_remote_relays`]).
//!
//! A remote with no policy is reached through any relay, as upstream. One with a policy is reached through those
//! relays alone: every datagram the endpoint would send it through another is dropped where datagrams are handed to
//! the relay transports ([`super::transports::TransportsSender::poll_send`], the one place both a connection's
//! packets on a concrete path and the Initials raced on every known address go through), and its `RemoteStateActor`
//! keeps no address, path or path being opened through another (`RemoteStateActor::apply_relay_policy`). Its IP and
//! custom addresses are never touched.
//!
//! The policies are shared by the socket, its senders and every actor, read where they are used, so an actor started
//! anew (after it idled out, or restarted with what came while it stopped) goes by the policy as it is. An entry is
//! kept until the caller takes it away (`None`): the caller bounds them (still.fail: a workspace's stations).

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock, RwLockReadGuard},
};

use iroh_base::{EndpointId, RelayUrl};

#[derive(Debug, Default, Clone)]
pub(crate) struct RelayPolicies {
    inner: Arc<RwLock<HashMap<EndpointId, BTreeSet<RelayUrl>>>>,
    #[cfg(any(test, feature = "test-utils"))]
    counts: Arc<std::sync::Mutex<HashMap<(RelayUrl, EndpointId), RelayDatagrams>>>,
}

/// ember: what was handed to a relay transport for one remote through one relay, and what a policy dropped instead
/// (tests).
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayDatagrams {
    /// Handed to the relay transport to send.
    pub sent: u64,
    /// Dropped: the remote's policy names no such relay.
    pub refused: u64,
}

impl RelayPolicies {
    /// Sets `remote`'s relays (`None`: any).
    pub(crate) fn set(&self, remote: EndpointId, relays: Option<BTreeSet<RelayUrl>>) {
        let mut inner = self.inner.write().expect("poisoned");
        match relays {
            Some(relays) => drop(inner.insert(remote, relays)),
            None => drop(inner.remove(&remote)),
        }
    }

    /// Whether `remote` may be reached through `relay`.
    pub(crate) fn allows(&self, remote: &EndpointId, relay: &RelayUrl) -> bool {
        Self::allows_in(&self.read(), remote, relay)
    }

    /// The policies, read: [`Self::set`] waits until this is let go. Held only across what does not wait (a sender's
    /// non-blocking poll), so that what it decides and what it hands on are of one policy.
    pub(crate) fn read(&self) -> RwLockReadGuard<'_, HashMap<EndpointId, BTreeSet<RelayUrl>>> {
        self.inner.read().expect("poisoned")
    }

    /// Whether `remote` may be reached through `relay`, by policies read.
    pub(crate) fn allows_in(policies: &HashMap<EndpointId, BTreeSet<RelayUrl>>, remote: &EndpointId, relay: &RelayUrl) -> bool {
        policies.get(remote).is_none_or(|relays| relays.contains(relay))
    }

    /// `remote`'s relays, where it has a policy.
    #[cfg(test)]
    pub(crate) fn get(&self, remote: &EndpointId) -> Option<BTreeSet<RelayUrl>> {
        self.inner.read().expect("poisoned").get(remote).cloned()
    }

    /// A datagram for `remote` through `relay` handed on (`sent`) or dropped (tests count them).
    #[allow(unused_variables)]
    pub(crate) fn counted(&self, relay: &RelayUrl, remote: &EndpointId, sent: bool) {
        #[cfg(any(test, feature = "test-utils"))]
        {
            let mut counts = self.counts.lock().expect("poisoned");
            let entry = counts.entry((relay.clone(), *remote)).or_default();
            if sent {
                entry.sent += 1;
            } else {
                entry.refused += 1;
            }
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn datagrams(&self, relay: &RelayUrl, remote: &EndpointId) -> RelayDatagrams {
        self.counts.lock().expect("poisoned").get(&(relay.clone(), *remote)).copied().unwrap_or_default()
    }
}
