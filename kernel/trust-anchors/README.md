# Production trust anchors

Every `*.der` file here (DER X.509, in name order) is a certificate authority the network
service trusts in production kernels (#221 stage D). A build can point at another directory
with `CLEAN_SLATE_TRUST_ANCHORS_DIR`.

The set is empty for now, so production TLS fails closed: no server is trusted. Test kernels
(the M7 lanes) never read this directory; they hand the service the M7 test CA
(`xtask/fixtures/m7/ca.crt`) instead, and only they compile it in.

Limits: at most 4 anchors and 2,560 bytes in all (`clean_slate_network::config`), and the
TLS client verifies ECDSA P-256 / SHA-256 chains only, so an RSA or P-384 root here would
never match. Choosing the public root set is a follow-up.
