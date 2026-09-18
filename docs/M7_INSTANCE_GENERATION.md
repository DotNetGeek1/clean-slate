# M7 instance generation follow-up

M7.7 wires `ResourceRef.instance_generation` for `ResourceClass::Network` to the live
`ServiceLifecycleController::authoritative_generation` for `NETWORK_SERVICE_ID`
(`0x0000_5200`).

## Still on generation `0` (pre-M7.7 debt)

| Resource class | Notes |
|----------------|-------|
| `PersistentObject` | Object id only; no service replacement epoch |
| `IpcEndpoint` | Endpoint identity is stable per creation |
| `BlockDevice` | Device id; separate block capability table generations |
| `LifecycleControl` | Separate lifecycle-control handle generations |
| `Audit` | Singleton audit reader resource |
| `ProcessControl` | Grants may carry a generation, but `lookup_live_target` still reports `0` until a dedicated process-generation lane lands |

Future lanes should call `live_instance_generation(service)` (or the pid variant for
supervised instances) when minting new capability records instead of hard-coding `0`.
