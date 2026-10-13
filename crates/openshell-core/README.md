# openshell-core

Shared types, constants, configuration, and helpers used across OpenShell
crates.

## Object Metadata

Top-level user-facing objects use a Kubernetes-style metadata convention. The
metadata shape provides:

- Stable server-generated ID.
- Human-readable name.
- Creation timestamp.
- Optional labels for filtering and automation.

Code that works with object metadata should use the traits in
`openshell_core::metadata` instead of reaching into protobuf fields directly:

```rust
use openshell_core::{ObjectId, ObjectLabels, ObjectName};

let id = sandbox.object_id();
let name = sandbox.object_name();
let labels = sandbox.object_labels();
```

Trait methods must tolerate missing metadata and return safe empty values rather
than panicking.

## Label Rules

Labels follow Kubernetes-style key and value conventions:

- Keys may include an optional DNS-prefix followed by `/`.
- Names are limited to alphanumeric characters plus `-`, `_`, and `.`.
- Values use the same character set and may be empty.
- Selectors use comma-separated `key=value` pairs with AND semantics.

Validate labels at API ingress before persisting objects.

## Inference Profiles

Provider inference profiles live in this crate so the gateway, sandbox, and
router agree on provider defaults. Profiles define:

- Auth header style.
- Default upstream headers.
- Client-supplied passthrough headers.
- Supported inference protocol shapes.

Do not duplicate provider-specific inference behavior in callers. Add shared
behavior here, then consume it from the gateway, sandbox, and router.

## Middleware Contracts

Built-in supervisor middleware identifiers, host-selector matching, and pure
configuration validation live in `openshell_core::middleware`. Policy admission
and the supervisor runtime consume the same contract without introducing a
dependency from the policy crate to the supervisor implementation.

## Protobuf Struct Conversion

Use `openshell_core::proto_struct` when crossing between `serde_json` values and
`prost_types::{Struct, Value}`. Both conversion directions live in this module;
JSON-to-protobuf conversion is fallible so callers cannot silently replace an
unrepresentable number.

## CDI policy provenance

The workload resolves trusted CDI context into filesystem requirements. Library
mounts expand to their parent directory; the expanded path must pass the same
broad-root rejection as other CDI destinations.

`FilesystemPolicy::cdi_requirements` is runtime-local provenance, retained by
policy clones for initial launch and subsequent execs. Protobuf and boundary
wire conversion do not accept it; the workload derives it from CDI context.
The sandbox processes deduplicated CDI targets sequentially: open a target,
validate its type and broad-root object identity, add matching Landlock rules
using that same descriptor, and close it before opening the next target.
Targets covered by authored ancestors are validated without adding a rule.
Only path requirements and root identities are retained; the number of open
CDI descriptors does not grow with the spec. Symlinks to legitimate library
directories remain supported. CDI validation and enforcement failures abort launch, including
when the authored Landlock compatibility is best effort. Other path sources
retain their existing opening behavior.

Original CDI mount destinations remain separate from expanded library parents.
The workload classifies their effective read-only flags rather than trusting
spec option defaults, and checks original directory mounts for writable
submounts using one mount-table snapshot per pass. An ordinary writable mount destination must
be a single regular file explicitly listed in authored `read_write` paths.
The sequential Landlock pass rechecks mount access on its opened descriptors.
CDI does not add write access to `/proc`; existing thread-name mediation applies.
Supplemental groups must already be supplied by the container runtime.

CDI Unix socket mounts are recorded as exact socket destinations, separately from
ordinary file mounts. Their opened objects must remain Unix sockets at each
launch or exec. They do not derive filesystem grants, expand to parent
directories, or require the writable-file allowlist, regardless of mount flags.
Communication follows the existing Unix IPC and inode permission checks; this
validation does not pin the endpoint for later pathname-based connections.
