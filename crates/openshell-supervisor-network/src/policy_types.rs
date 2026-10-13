// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral network policy inputs, results, and generation guards.
//!
//! Both [`crate::opa::OpaEngine`] (YAML policies) and
//! [`crate::cedar_only::CedarOnlyEngine`] (Cedar policies) speak these types,
//! so decision points never depend on which engine a sandbox uses. Endpoint
//! configs are carried as `regorus::Value` because that is the shape the L7
//! config parser reads; it is plain data here, never evaluated.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use miette::Result;
use tokio::sync::watch;

/// Network action returned by a network policy decision.
///
/// - `Allow`: endpoint + binary explicitly matched in a network policy
/// - `Deny`: no matching policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    Allow { matched_policy: Option<String> },
    Deny { reason: String },
}

/// Endpoint identity and metadata captured with one policy generation.
#[derive(Debug, Clone)]
pub struct MatchedEndpoint {
    pub policy_name: String,
    pub endpoint_index: usize,
    pub endpoint: regorus::Value,
}

/// Policy-DNS eligible endpoint metadata captured from one policy generation.
///
/// This is policy data only. It deliberately contains no process identity or
/// network authorization decision.
#[derive(Debug, Clone)]
pub struct PolicyDnsEligibilitySnapshot {
    pub endpoints: Vec<MatchedEndpoint>,
    pub generation: u64,
    /// The generation is a fail-closed quarantine, so every name is refused.
    pub fail_closed: bool,
}

/// Atomic policy result used to authorize and materialize one egress request.
#[derive(Debug, Clone)]
pub struct EgressAuthorization {
    pub action: NetworkAction,
    pub endpoint_configs: Vec<regorus::Value>,
    pub matched_endpoints: Vec<MatchedEndpoint>,
    pub exact_declared_endpoint_host: bool,
    pub generation: u64,
    /// For a Cedar sandbox's allowed connection, how its resolved addresses
    /// are checked; `None` for YAML, whose endpoint configs carry
    /// `allowed_ips` instead.
    pub cedar_destination: Option<crate::cedar_only::CedarDestination>,
}

/// Input for a network access policy evaluation.
pub struct NetworkInput {
    pub host: String,
    pub port: u16,
    pub binary_path: PathBuf,
    pub binary_sha256: String,
    /// Ancestor binary paths from process tree walk (parent, grandparent, ...).
    pub ancestors: Vec<PathBuf>,
    /// Absolute paths extracted from `/proc/<pid>/cmdline` of the socket-owning
    /// process and its ancestors. Captures script paths (e.g. `/usr/local/bin/claude`)
    /// that don't appear in `/proc/<pid>/exe` because the interpreter (node) is the exe.
    pub cmdline_paths: Vec<PathBuf>,
}

/// Generation guard captured when an HTTP tunnel or request path starts.
#[derive(Clone, Debug)]
pub struct PolicyGenerationGuard {
    captured_generation: u64,
    current_generation: Arc<AtomicU64>,
    generation_rx: watch::Receiver<u64>,
}

/// Builds a [`PolicyGenerationGuard`] for any state holding a plain
/// `Arc<AtomicU64>` generation counter and matching `watch::Sender<u64>`.
///
/// `OpaEngine`, `CedarOnlyEngine`, and the Cedar middleware state all use
/// this shape, so the guard itself (and callers that only read it, e.g.
/// DNS-staleness checks) don't need to know which one produced it.
///
/// # Errors
///
/// Returns an error if `current_generation_value` differs from
/// `expected_generation`.
pub(crate) fn generation_guard_for(
    expected_generation: u64,
    current_generation_value: u64,
    current_generation: &Arc<AtomicU64>,
    generation_tx: &watch::Sender<u64>,
) -> Result<PolicyGenerationGuard> {
    if current_generation_value != expected_generation {
        return Err(miette::miette!(
            "policy changed before HTTP relay started [expected_generation:{expected_generation} current_generation:{current_generation_value}]"
        ));
    }
    Ok(PolicyGenerationGuard {
        captured_generation: current_generation_value,
        current_generation: Arc::clone(current_generation),
        generation_rx: generation_tx.subscribe(),
    })
}

impl PolicyGenerationGuard {
    pub fn captured_generation(&self) -> u64 {
        self.captured_generation
    }

    pub fn current_generation(&self) -> u64 {
        self.current_generation.load(Ordering::Acquire)
    }

    pub fn is_stale(&self) -> bool {
        self.current_generation() != self.captured_generation
    }

    pub fn ensure_current(&self) -> Result<()> {
        if self.is_stale() {
            return Err(miette::miette!(
                "policy generation is stale [captured_generation:{} current_generation:{}]",
                self.captured_generation(),
                self.current_generation(),
            ));
        }
        Ok(())
    }

    /// Wait until the policy generation changes.
    ///
    /// Relay boundaries use this to close even an idle or raw stream as soon
    /// as a new generation (including fail-closed quarantine) is published.
    pub async fn wait_until_stale(&self) {
        let mut receiver = self.generation_rx.clone();
        while !self.is_stale() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
