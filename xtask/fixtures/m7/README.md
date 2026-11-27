# M7 TLS test fixtures

These certificates and private keys are test-only fixtures for the M7 TLS
lanes (`cargo xtask gen-m7-fixture-certs` in `xtask/src/m7_certs.rs`).

They are public: this directory is in the git history. They must never be
used for anything real, and nothing outside the test harness should trust
this CA.

The generator names the CA `Clean-Slate M7 Test CA`, the server certificate
`m7.fixture.test`, and the other certificate `wrong.fixture.test`. The
private keys are `server.key`, `server.key.pem`, `server-wrong-name.key`,
and `server-wrong-name.key.pem`.

Only test kernels compile `ca.crt` in (`kernel/src/service/net_launch.rs`, the M7
feature sets) and hand it to the network service at launch; the service image and
production kernels never contain it.
