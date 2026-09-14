# Native SDK & Applications

Rust is the preferred first-class language for native Clean-Slate development, but the operating system ABI should remain language-neutral enough for C, C++, Zig, Go, .NET, scripting runtimes, and other ecosystems to target later.

## Native application model

A native application should consist conceptually of:

```text
immutable application image
        +
private mutable state
        +
explicit capabilities
```

The executable package must not gain ambient access to the user's machine simply because it was launched.

## Rust target

A future Rust target could look like:

```text
x86_64-clean_slate
```

The native Rust SDK should wrap stable Clean-Slate userspace APIs and IPC protocols rather than encouraging ordinary applications to depend directly on raw kernel syscalls.

This keeps the kernel free to evolve while maintaining a durable application contract.

## CLI/SDK experience

The intended developer experience is deliberately simple:

```bash
cs new myapp
cd myapp
cs run
```

Expected SDK commands include:

```text
cs new
cs build
cs run
cs test
cs package
cs install
cs deploy
cs debug
cs doctor
cs audit
cs capabilities
cs trace
```

During early development, `cs run` can build the application, launch a QEMU Clean-Slate instance, copy/install the application into the guest, launch it, and stream logs back to the developer.

## Application manifest

A native package should explicitly describe its capabilities.

Example:

```toml
[application]
name = "Image Viewer"
version = "0.1.0"

[capabilities]
filesystem = ["user-selected-files"]
gpu = ["render"]
network = false
```

The manifest is both a packaging declaration and a security contract.

## Typed capabilities

Rust makes it practical to express authority in the type system.

Conceptually:

```rust
FileCapability<ReadOnly>
FileCapability<ReadWrite>
```

Code holding a read-only capability should not expose write operations.

The Rust SDK should use types to make accidental privilege expansion difficult.

## First-party crates

Potential native SDK crates/modules include:

```text
cs-core
cs-ui
cs-files
cs-net
cs-audio
cs-storage
cs-ipc
cs-process
cs-security
```

Names are provisional; the important point is API separation by system responsibility.

## UI toolkit

The preferred native GUI should not require bundling a browser engine.

A first-party Rust UI toolkit should aim for:

- fast startup;
- modest memory usage;
- GPU acceleration;
- accessibility;
- DPI-independent rendering;
- strong text/font handling;
- asynchronous event handling;
- explicit capability interactions for user-selected files/devices.

Electron and similar stacks can remain supported through compatibility runtimes, but native Clean-Slate applications should have a materially lighter path.

## Stable ABI boundary

The native public application contract should be expressed through stable userspace service protocols/ABIs.

Normal applications should not care about the current internal implementation of the scheduler, filesystem service, compositor, or kernel object layout.

A language-neutral ABI underneath the Rust bindings avoids coupling Clean-Slate's ecosystem permanently to one implementation language.

## Application packages

A future package format may use a `.csapp` container.

Conceptually:

```text
MyApp.csapp/
  manifest
  resources/
  x86_64/app
  aarch64/app     # possible future target
```

Multi-architecture packages should be possible without changing the application-facing SDK.

## Development-time sandbox tooling

The security model should be useful during development.

Examples:

```bash
cs run --deny network
cs run --memory-limit 256M
cs run --trace capabilities
cs audit myapp.csapp
```

A capability trace might report:

```text
GPU.render                GRANTED
File.read: photo.jpg      GRANTED
Network.connect           DENIED
```

This makes security and privacy behaviour testable rather than merely declarative.

## Native development principle

Building a native Clean-Slate application should eventually be easier and lighter than shipping a compatibility application.
