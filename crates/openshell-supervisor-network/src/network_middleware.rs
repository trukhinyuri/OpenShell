// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral network middleware selection and state.
//!
//! [`MiddlewareConfigs`] holds one policy revision's `network_middlewares`
//! and selects the ordered chain for a destination host in Rust, with the
//! same host-selector semantics as endpoint admission. Both engines use it:
//! a YAML sandbox reads the configs out of its Rego data, and a Cedar sandbox
//! builds them from the policy proto.
//!
//! [`MiddlewareState`] is a Cedar sandbox's live middleware: the active
//! configs, the connected service registry, and a generation counter that
//! each middleware change and each committed runtime configuration advance.
//! It replaces the empty-policy OPA engine Cedar sandboxes once carried for
//! this purpose, so a Cedar sandbox evaluates no Rego.
//!
//! Configs are carried as `regorus::Value`, the shape the Rego data gives
//! them. It is plain data here, never evaluated.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_core::host_pattern::HostSelector;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry};
use tokio::sync::watch;

use crate::policy_types::{PolicyGenerationGuard, generation_guard_for};
use crate::policy_value::{get_field, get_str, get_str_array};

/// Field under which each config carries its `network_middlewares` key.
const POLICY_KEY_FIELD: &str = "__openshell_policy_key";

/// The `network_middlewares` of one policy revision, ready for selection.
///
/// Cloning is cheap and shares the configs.
#[derive(Clone, Debug, Default)]
pub struct MiddlewareConfigs(Arc<[regorus::Value]>);

impl MiddlewareConfigs {
    /// Reads the `network_middlewares` object of a policy's data.
    ///
    /// An undefined value (no middleware section) yields no configs.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not an object of objects keyed by
    /// strings.
    pub fn from_policy_value(value: &regorus::Value) -> Result<Self> {
        let configs = match value {
            regorus::Value::Undefined => Vec::new(),
            regorus::Value::Object(configs) => configs
                .iter()
                .map(|(name, config)| {
                    let regorus::Value::String(_) = name else {
                        return Err(miette::miette!("network_middlewares keys must be strings"));
                    };
                    let regorus::Value::Object(fields) = config else {
                        return Err(miette::miette!(
                            "network middleware config {name:?} must be an object"
                        ));
                    };
                    let fields = fields
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .chain(std::iter::once((
                            regorus::Value::String(POLICY_KEY_FIELD.into()),
                            name.clone(),
                        )))
                        .collect::<std::collections::BTreeMap<_, _>>();
                    Ok(fields.into())
                })
                .collect::<Result<_>>()?,
            other => {
                return Err(miette::miette!(
                    "network_middlewares must be an object, got {other:?}"
                ));
            }
        };
        Ok(Self(configs.into()))
    }

    /// Reads the `network_middlewares` of a policy proto.
    ///
    /// Produces the same configs a YAML sandbox reads from the Rego data
    /// built from the same proto.
    ///
    /// # Errors
    ///
    /// Returns an error if the configs cannot be converted, which a valid
    /// proto never causes.
    pub fn from_proto(policy: &ProtoSandboxPolicy) -> Result<Self> {
        let value = serde_json::from_value::<regorus::Value>(serde_json::Value::Object(
            crate::policy_data::network_middlewares_json(policy),
        ))
        .map_err(|e| miette::miette!("failed to build network middleware configs: {e}"))?;
        Self::from_policy_value(&value)
    }

    /// Returns the ordered middleware chain whose selectors match `host`.
    ///
    /// # Errors
    ///
    /// Returns an error if a selector or `on_error` value is invalid, or more
    /// stages match than the platform allows.
    pub fn select(&self, host: &str) -> Result<Vec<ChainEntry>> {
        let mut entries = Vec::new();
        for config in self.0.iter() {
            if selector_matches(config, host)? {
                if entries.len() >= openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES {
                    return Err(miette::miette!(
                        "selected middleware stage count exceeds platform maximum {}",
                        openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES
                    ));
                }
                entries.push(chain_entry_from_value(config)?);
            }
        }
        openshell_supervisor_middleware::sort_chain_entries(&mut entries);
        Ok(entries)
    }

    /// Returns the number of configs.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

fn selector_matches(config: &regorus::Value, host: &str) -> Result<bool> {
    let Some(selector) = get_field(config, "endpoints") else {
        return Ok(false);
    };
    let include = get_str_array(selector, "include");
    let exclude = get_str_array(selector, "exclude");
    let selector = HostSelector::new(&include, &exclude).map_err(|error| miette::miette!(error))?;
    Ok(selector.matches(host))
}

fn chain_entry_from_value(value: &regorus::Value) -> Result<ChainEntry> {
    let name = get_str(value, POLICY_KEY_FIELD).unwrap_or_default();
    let implementation = get_str(value, "middleware").unwrap_or_default();
    Ok(ChainEntry {
        name,
        implementation,
        order: get_field(value, "order")
            .and_then(|value| match value {
                regorus::Value::Number(number) => number.as_i64(),
                _ => None,
            })
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or_default(),
        config: get_field(value, "config")
            .map(regorus_value_to_struct)
            .unwrap_or_default(),
        on_error: openshell_supervisor_middleware::OnError::parse(
            get_str(value, "on_error").as_deref().unwrap_or_default(),
        )?,
    })
}

fn regorus_value_to_struct(value: &regorus::Value) -> prost_types::Struct {
    let regorus::Value::Object(map) = value else {
        return prost_types::Struct::default();
    };
    prost_types::Struct {
        fields: map
            .iter()
            .filter_map(|(key, value)| match key {
                regorus::Value::String(key) => {
                    Some((key.to_string(), regorus_value_to_prost(value)))
                }
                _ => None,
            })
            .collect(),
    }
}

fn regorus_value_to_prost(value: &regorus::Value) -> prost_types::Value {
    use prost_types::{ListValue, Struct, Value, value::Kind};
    Value {
        kind: Some(match value {
            regorus::Value::Bool(value) => Kind::BoolValue(*value),
            regorus::Value::Number(value) => Kind::NumberValue(value.as_f64().unwrap_or_default()),
            regorus::Value::String(value) => Kind::StringValue(value.to_string()),
            regorus::Value::Array(values) => Kind::ListValue(ListValue {
                values: values.iter().map(regorus_value_to_prost).collect(),
            }),
            regorus::Value::Object(values) => Kind::StructValue(Struct {
                fields: values
                    .iter()
                    .filter_map(|(key, value)| match key {
                        regorus::Value::String(key) => {
                            Some((key.to_string(), regorus_value_to_prost(value)))
                        }
                        _ => None,
                    })
                    .collect(),
            }),
            _ => Kind::NullValue(0),
        }),
    }
}

/// The middleware configs and services in effect at one time.
#[derive(Clone)]
pub struct ActiveMiddleware {
    pub configs: MiddlewareConfigs,
    pub runner: ChainRunner,
}

/// A Cedar sandbox's live middleware configs, services, and generation.
///
/// The generation advances when the service registry is replaced and when a
/// runtime configuration is committed, under the write lock, so a reader
/// that observes a generation under the read lock also sees the middleware
/// that produced it. It is independent of the Cedar policy generation: a
/// middleware-only change does not close inspected tunnels, which keep the
/// middleware they started with.
pub struct MiddlewareState {
    active: RwLock<ActiveMiddleware>,
    generation: Arc<AtomicU64>,
    generation_tx: watch::Sender<u64>,
}

impl std::fmt::Debug for MiddlewareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareState")
            .field(
                "configs",
                &self.active.read().map(|active| active.configs.len()).ok(),
            )
            .field("generation", &self.current_generation())
            .finish_non_exhaustive()
    }
}

impl MiddlewareState {
    /// Starts at generation 0 with `configs` and no connected services.
    pub fn new(configs: MiddlewareConfigs) -> Self {
        let (generation_tx, _) = watch::channel(0);
        Self {
            active: RwLock::new(ActiveMiddleware {
                configs,
                runner: ChainRunner::default(),
            }),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
        }
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, ActiveMiddleware>> {
        self.active
            .read()
            .map_err(|_| miette::miette!("middleware state lock poisoned"))
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, ActiveMiddleware>> {
        self.active
            .write()
            .map_err(|_| miette::miette!("middleware state lock poisoned"))
    }

    /// Advances the generation. Callers hold the write lock.
    fn advance_generation(&self) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.generation_tx.send_replace(generation);
        generation
    }

    /// Returns the current middleware generation.
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Pins `expected_generation`.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is already stale.
    pub fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        generation_guard_for(
            expected_generation,
            self.current_generation(),
            &self.generation,
            &self.generation_tx,
        )
    }

    /// Selects the chain for `host` and returns the generation it came from.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or selection fails (see
    /// [`MiddlewareConfigs::select`]).
    pub fn select_with_generation(&self, host: &str) -> Result<(Vec<ChainEntry>, u64)> {
        let active = self.read()?;
        let generation = self.current_generation();
        Ok((active.configs.select(host)?, generation))
    }

    /// Returns the configs and services in effect now, for a tunnel to keep.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn snapshot(&self) -> Result<ActiveMiddleware> {
        Ok(self.read()?.clone())
    }

    /// Returns the services in effect now.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn runner(&self) -> Result<ChainRunner> {
        Ok(self.read()?.runner.clone())
    }

    /// Replaces the service registry and advances the generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn replace_registry(&self, registry: MiddlewareRegistry) -> Result<()> {
        let mut active = self.write()?;
        active.runner = active.runner.with_replacement_registry(registry);
        self.advance_generation();
        Ok(())
    }

    /// Activates `configs`, and `registry` when given, as a new generation.
    ///
    /// `publish` runs after the generation advances, so existing guards are
    /// already stale, and before the new middleware is visible: readers stay
    /// blocked until it returns. It must not call back into this state.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned; nothing is changed then and
    /// `publish` is not called.
    pub fn commit(
        &self,
        configs: MiddlewareConfigs,
        registry: Option<MiddlewareRegistry>,
        publish: impl FnOnce(),
    ) -> Result<PolicyGenerationGuard> {
        let mut active = self.write()?;
        let runner = registry.map(|registry| active.runner.with_replacement_registry(registry));
        let generation = self.advance_generation();
        publish();
        active.configs = configs;
        if let Some(runner) = runner {
            active.runner = runner;
        }
        drop(active);
        self.generation_guard(generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matching_configs(count: usize) -> MiddlewareConfigs {
        let configs = (0..count)
            .map(|index| {
                (
                    format!("stage-{index}"),
                    serde_json::json!({
                        "middleware": "openshell/regex",
                        "endpoints": {"include": ["api.example.com"]}
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        MiddlewareConfigs::from_policy_value(&regorus::Value::from(serde_json::Value::Object(
            configs,
        )))
        .expect("configs parse")
    }

    #[test]
    fn select_accepts_maximum_selected_stages() {
        let chain = matching_configs(openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES)
            .select("api.example.com")
            .expect("maximum selected chain");
        assert_eq!(
            chain.len(),
            openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES
        );
    }

    #[test]
    fn select_rejects_selected_stages_over_capacity() {
        let error =
            matching_configs(openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES + 1)
                .select("api.example.com")
                .expect_err("selected chain over capacity");
        assert!(
            error
                .to_string()
                .contains("selected middleware stage count exceeds platform maximum 10")
        );
    }

    fn middleware_proto() -> ProtoSandboxPolicy {
        let middleware = |order: i32, include: &str, exclude: &[&str]| {
            openshell_core::proto::NetworkMiddlewareConfig {
                middleware: "openshell/regex".to_string(),
                order,
                endpoints: Some(openshell_core::proto::MiddlewareEndpointSelector {
                    include: vec![include.to_string()],
                    exclude: exclude.iter().map(ToString::to_string).collect(),
                }),
                ..Default::default()
            }
        };
        let mut policy = ProtoSandboxPolicy::default();
        policy
            .network_middlewares
            .insert("late".to_string(), middleware(20, "**.example.com", &[]));
        policy.network_middlewares.insert(
            "early".to_string(),
            middleware(10, "*.example.com", &["trusted.example.com"]),
        );
        policy
    }

    /// A Cedar sandbox selects from the proto exactly what a YAML sandbox
    /// selects from the Rego data built from the same proto.
    #[test]
    fn proto_configs_select_like_the_rego_data_built_from_the_same_proto() {
        let policy = middleware_proto();
        let opa = crate::opa::OpaEngine::from_proto(&policy).expect("YAML engine loads");
        let configs = MiddlewareConfigs::from_proto(&policy).expect("configs build");
        for host in [
            "api.example.com",
            "trusted.example.com",
            "deep.api.example.com",
            "example.org",
        ] {
            let input = crate::policy_types::NetworkInput {
                host: host.to_string(),
                port: 443,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: String::new(),
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            };
            let (rego, _) = opa
                .query_middleware_chain_with_generation(&input)
                .expect("Rego selection");
            let rust = configs.select(host).expect("Rust selection");
            let names = |chain: &[ChainEntry]| {
                chain
                    .iter()
                    .map(|entry| (entry.name.clone(), entry.order))
                    .collect::<Vec<_>>()
            };
            assert_eq!(names(&rust), names(&rego), "host {host}");
        }
    }

    #[test]
    fn commit_advances_the_generation_before_publishing() {
        let state = MiddlewareState::new(MiddlewareConfigs::default());
        let before = state.generation_guard(0).expect("current guard");
        let mut stale_during_publish = false;
        let guard = state
            .commit(
                MiddlewareConfigs::from_proto(&middleware_proto()).expect("configs build"),
                None,
                || stale_during_publish = before.is_stale(),
            )
            .expect("commit");
        assert!(stale_during_publish);
        assert_eq!(guard.captured_generation(), 1);
        let (chain, generation) = state
            .select_with_generation("api.example.com")
            .expect("select");
        assert_eq!(generation, 1);
        assert_eq!(chain.len(), 2);
    }
}
