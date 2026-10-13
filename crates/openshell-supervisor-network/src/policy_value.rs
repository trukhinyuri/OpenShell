// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Field accessors for policy data held as `regorus::Value`.
//!
//! Endpoint configs and middleware configs are carried as `regorus::Value`,
//! the shape the L7 config parser reads. These accessors only read that data;
//! nothing here evaluates Rego.

/// Extracts a string from a `regorus::Value` object field.
pub fn get_str(val: &regorus::Value, key: &str) -> Option<String> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::String(s)) => Some(s.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Extracts a bool from a `regorus::Value` object field.
pub fn get_bool(val: &regorus::Value, key: &str) -> Option<bool> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::Bool(b)) => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

/// Extracts a string array from a `regorus::Value` object field.
pub fn get_str_array(val: &regorus::Value, key: &str) -> Vec<String> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let regorus::Value::String(s) = v {
                        Some(s.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => vec![],
        },
        _ => vec![],
    }
}

/// Returns a field of a `regorus::Value` object.
pub fn get_field<'a>(val: &'a regorus::Value, key: &str) -> Option<&'a regorus::Value> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => map.get(&key_val),
        _ => None,
    }
}
