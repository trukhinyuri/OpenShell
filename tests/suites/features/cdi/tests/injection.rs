// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hardware-free CDI injection checks against the installed tmachine gateway.

use openshell_conformance::OpenShellRunner;
use serde_json::{Value, json};
use std::time::Duration;

const PROBE: &str = r#"
set -eu
test "${TMACHINE_CDI_SPEC_0:-}" = "${TMACHINE_CDI_DEVICE_0:+fixture}"
test "${TMACHINE_CDI_SPEC_1:-}" = "${TMACHINE_CDI_DEVICE_1:+fixture}"
for index in 0 1; do
    eval "selected=\${TMACHINE_CDI_DEVICE_${index}:-}"
    mount=/usr/share/openshell-cdi/device-$index
    if [ "$selected" = "$index" ]; then
        test "$(cat "$mount")" = "tmachine-cdi-$index"
        printf 'device=%s\n' "$index"
    else
        test -z "$selected"
        test ! -e "$mount"
    fi
done
test -z "${TMACHINE_CDI_UNRELATED:-}"
"#;

async fn check_case(
    case: &str,
    gpu: Option<&str>,
    devices: Option<&[&str]>,
    probe: &str,
    expected_devices: Option<&[&str]>,
    expected_error: Option<&str>,
) {
    let mut runner = OpenShellRunner::from_env(case).expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let info = runner
            .step("preflight/driver")
            .description("gateway has one Docker compute driver")
            .with_timeout(Duration::from_secs(10))
            .run(&["gateway", "info", "--output", "json"])
            .await
            .map_err(|error| error.to_string())?;
        info.require_success()?;
        let info_json: Value = info.json().map_err(|error| error.to_string())?;
        let drivers = info_json["compute_drivers"]
            .as_array()
            .ok_or_else(|| "gateway did not report compute drivers".to_string())?;
        let driver = match drivers.as_slice() {
            [driver] => driver["name"].as_str().unwrap_or_default(),
            _ => return Err("CDI suite requires exactly one compute driver".to_string()),
        };
        if driver != "docker" {
            return Err(format!("CDI suite requires Docker, got {driver:?}"));
        }

        let sandbox = format!("cdi-{}", runner.id());
        runner.track_sandbox(&sandbox);
        let config = devices.map(|devices| json!({driver: {"cdi_devices": devices}}).to_string());
        let mut args = vec!["sandbox", "create", "--name", &sandbox, "--no-tty"];
        if let Some(count) = gpu {
            args.push("--gpu");
            if !count.is_empty() {
                args.push(count);
            }
        }
        if let Some(config) = config.as_deref() {
            args.extend(["--driver-config-json", config]);
        }
        args.extend(["--", "sh", "-c", probe]);
        let run = runner
            .step("cdi/injection")
            .description(case)
            .with_timeout(Duration::from_secs(300))
            .run(&args)
            .await
            .map_err(|error| error.to_string())?;
        if let Some(expected_error) = expected_error {
            if run.success()
                || !format!("{}\n{}", run.stdout(), run.stderr()).contains(expected_error)
            {
                return Err(run.failure_diagnostic(&format!(
                    "creation fails with a CDI diagnostic containing {expected_error:?}"
                )));
            }
        } else {
            run.require_success()?;
            let mut selected = run
                .stdout()
                .lines()
                .filter_map(|line| line.strip_prefix("device="))
                .collect::<Vec<_>>();
            selected.sort();
            if let Some(expected) = expected_devices {
                if selected != expected {
                    return Err(
                        run.failure_diagnostic(&format!("selected devices are {expected:?}"))
                    );
                }
            } else if selected.len() != 1 || !matches!(selected[0], "0" | "1") {
                return Err(run.failure_diagnostic("default selection injects exactly one device"));
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("CDI test failed:\n{error}");
    }
}

#[tokio::test]
async fn no_gpu_request_has_no_cdi_edits() {
    check_case("cdi-none", None, None, r#"
set -eu
test -z "${TMACHINE_CDI_SPEC_0:-}${TMACHINE_CDI_SPEC_1:-}${TMACHINE_CDI_DEVICE_0:-}${TMACHINE_CDI_DEVICE_1:-}${TMACHINE_CDI_UNRELATED:-}"
for index in 0 1; do
    test ! -e /usr/share/openshell-cdi/device-$index
done
"#, Some(&[]), None).await;
}

#[tokio::test]
async fn explicit_device_injects_only_its_edits() {
    check_case(
        "cdi-explicit",
        Some("1"),
        Some(&["nvidia.com/gpu=1"]),
        PROBE,
        Some(&["1"]),
        None,
    )
    .await;
}

#[tokio::test]
async fn explicit_multiple_devices_apply_both_specs() {
    check_case(
        "cdi-multiple",
        Some("2"),
        Some(&["nvidia.com/gpu=1", "nvidia.com/gpu=0"]),
        PROBE,
        Some(&["0", "1"]),
        None,
    )
    .await;
}

#[tokio::test]
async fn default_gpu_request_injects_one_device() {
    check_case("cdi-default", Some(""), None, PROBE, None, None).await;
}

#[tokio::test]
async fn count_request_injects_two_devices() {
    check_case("cdi-count", Some("2"), None, PROBE, Some(&["0", "1"]), None).await;
}

#[tokio::test]
async fn unavailable_count_is_rejected() {
    check_case(
        "cdi-too-many",
        Some("3"),
        None,
        "exit 0",
        None,
        Some("only 2 selectable"),
    )
    .await;
}

#[tokio::test]
async fn unknown_explicit_device_is_rejected() {
    check_case(
        "cdi-unknown",
        Some("1"),
        Some(&["nvidia.com/gpu=missing"]),
        "exit 0",
        None,
        Some("unresolvable CDI devices"),
    )
    .await;
}

#[tokio::test]
async fn explicit_device_count_mismatch_is_rejected() {
    check_case(
        "cdi-mismatch",
        Some("2"),
        Some(&["nvidia.com/gpu=0"]),
        "exit 0",
        None,
        Some("driver_config.cdi_devices"),
    )
    .await;
}
