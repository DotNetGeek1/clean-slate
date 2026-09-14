# Compatibility Strategy

Compatibility is a first-class Clean-Slate requirement. A technically elegant OS that forces users back to Windows for their real applications has failed as a desktop platform.

## Application personalities

Clean-Slate should support multiple application personalities above the native kernel and service model:

```text
Applications
    |
    +-- Native Clean-Slate
    +-- Linux personality
    +-- Windows personality/runtime
    +-- MicroVM fallback
```

The user should not need to understand the implementation details in normal use.

## Linux compatibility

The first practical compatibility target is Linux userspace.

The project should begin by supporting unmodified ELF64 applications that expect the Linux syscall ABI. Compatibility can then grow toward a useful Linux environment with libc, shells, CLI tools, graphical applications, and package import.

Early target sequence:

1. unmodified Linux `hello` binary;
2. BusyBox or equivalent shell/toolset;
3. Git and networking/TLS;
4. graphical Linux application;
5. Doom;
6. VS Code;
7. Firefox/VLC/GIMP-class software.

Linux package formats such as `.deb`, `.rpm`, or AppImage should eventually be imported into isolated Clean-Slate application domains rather than turning the base OS into a hidden Linux distribution.

A package importer can resolve dependencies and construct an app-local Linux filesystem/runtime.

## Windows compatibility

Do not start by recreating Win32/NT from scratch.

The likely bootstrap path is to reuse mature open-source compatibility technology such as Wine/Proton, initially hosted through the Linux compatibility personality if necessary.

Longer term, Windows applications may run through a more direct Clean-Slate Windows runtime backed by native system services.

The compatibility stack must eventually account for substantial Windows behaviour, including:

- PE loading;
- Windows handles and synchronization objects;
- NT object semantics;
- registry;
- services;
- COM/OLE/RPC;
- Windows filesystem behaviour;
- exception handling;
- DLL loading;
- .NET runtimes;
- graphics/DirectX translation;
- installers/MSI;
- application-specific historical quirks.

## Per-application compatibility environments

Windows applications should receive isolated virtual Windows state rather than sharing one machine-wide mutable prefix.

Conceptually:

```text
Application Domain
  +-- virtual C:\
  +-- virtual registry
  +-- runtime version
  +-- app-private mutable state
  +-- capability mappings to Clean-Slate resources
```

This allows different applications to carry different compatibility settings without contaminating the rest of the system.

## Compatibility profiles

Application-specific profiles are acceptable when they represent generic compatibility fixes or historical quirks.

They must not become hidden ports of showcase applications. The canonical acceptance applications should run through generic compatibility infrastructure.

Profiles may control runtime versions, graphics translation, timer behaviour, API quirks, hardware identity, or other bounded compatibility settings.

## Windows microVM fallback

For applications that cannot run reliably under API translation, Clean-Slate may use an actual Windows microVM.

The VM should expose only selected resources through brokers:

- filesystem capabilities;
- clipboard;
- display/window integration;
- audio;
- network;
- optional GPU acceleration.

The application should appear as integrated as practical rather than forcing the user to operate a full nested desktop.

Windows licensing requirements remain the user's responsibility and must be respected.

## Compatibility ladder

Preferred application path:

1. Native Clean-Slate.
2. Linux personality/runtime.
3. Windows API compatibility runtime.
4. Windows microVM.

This lets compatibility degrade gracefully rather than becoming all-or-nothing.

## Hardware compatibility

Hardware compatibility should use a separate ladder:

1. Native sandboxed Clean-Slate driver.
2. Declarative/generated driver where suitable.
3. Linux driver domain.
4. Device passthrough to a specialized VM when unavoidable.

## Linux driver domain

A powerful bootstrap strategy is to use a small isolated Linux instance as a hardware-driver provider.

Linux already contains broad support for Wi-Fi, Bluetooth, USB, storage, audio, webcams, and other devices. Rather than making Linux the OS foundation, Clean-Slate can quarantine it as a driver domain and expose standardized virtual devices/services back to the host.

Example:

```text
Intel Wi-Fi hardware
      |
Linux driver domain
      |
Clean-Slate bridge
      |
standard Clean-Slate network interface
```

The Linux domain must remain untrusted and constrained by CPU/memory limits, immutable state, explicit device assignment, and IOMMU protections.

## VirtIO

VirtIO is the preferred early virtual hardware interface for QEMU and may also inform driver-domain bridges.

Initial targets should include:

- virtio-blk;
- virtio-net;
- virtio-gpu;
- virtio-input;
- virtio-sound where practical.

## GPU compatibility

GPUs are expected to be one of the hardest hardware areas due to kernel drivers, userspace drivers, shader compilers, memory management, display engines, Vulkan/OpenGL, video acceleration, power management, HDR/VRR, and multi-monitor support.

Early Clean-Slate graphics should therefore progress through:

1. UEFI framebuffer;
2. VirtIO GPU;
3. graphics/driver domain experiments;
4. native support for selected physical GPU families.

## Canonical end-user interoperability test

A meaningful compatibility test is not merely launching applications.

Example flow:

1. Download an archive in a Linux Firefox build.
2. Open it with Windows 7-Zip.
3. Extract a source project.
4. Open the same project in Linux VS Code.
5. Build it with Linux tooling.
6. Run the produced application.
7. Copy/paste and drag/drop between applications.
8. Reboot and continue working.

Linux and Windows applications should perceive familiar paths while internally referencing the same capability-controlled Clean-Slate objects.
