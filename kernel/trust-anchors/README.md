# Production trust anchors

Every `*.der` file here (DER X.509, in name order) is a certificate authority the network
service trusts in production kernels (#221). A build can point at another directory with
`CLEAN_SLATE_TRUST_ANCHORS_DIR`. Test kernels (the M7 lanes) never read this directory; they
hand the service the M7 test CA (`xtask/fixtures/m7/ca.crt`) instead, and only they compile it
in.

## The bundled set

31 public roots, 28,973 bytes, taken from the Mozilla root store as Ubuntu's
`ca-certificates` 20260816 ships it (`/usr/share/ca-certificates/mozilla`). They are the
roots behind most public TLS servers: Let's Encrypt (ISRG), Google Trust Services, DigiCert,
Amazon, Sectigo/USERTrust/COMODO, GlobalSign, Microsoft, GoDaddy/Starfield and SSL.com, in
both their RSA and ECDSA generations. Roots Mozilla has removed or distrusted (Entrust,
DigiCert Global Root CA, the original GlobalSign Root CA, Baltimore) are not here.

Limits (`clean_slate_network::config`): at most 32 anchors and 32,696 bytes in all, on the 8
read-only pages the kernel maps into the service. A set that does not fit fails the kernel
build (`TrustAnchors::pack`). The TLS client verifies RSA (PKCS#1 v1.5 with SHA-256/384/512
for certificates, PSS for the handshake signature), ECDSA P-256/SHA-256 and P-384/SHA-384.

To change the set, add or remove `.der` files and update the table. Check a file with
`openssl x509 -inform der -in <file> -noout -subject -fingerprint -sha256`.

| File | Subject | Expires | SHA-256 |
|------|---------|---------|---------|
| `amazon-root-ca-1.der` | C=US,O=Amazon,CN=Amazon Root CA 1 | 2038-Jan-17 | 8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e |
| `amazon-root-ca-2.der` | C=US,O=Amazon,CN=Amazon Root CA 2 | 2040-May-26 | 1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4 |
| `amazon-root-ca-3.der` | C=US,O=Amazon,CN=Amazon Root CA 3 | 2040-May-26 | 18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4 |
| `amazon-root-ca-4.der` | C=US,O=Amazon,CN=Amazon Root CA 4 | 2040-May-26 | e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092 |
| `comodo-ecc-certification-authority.der` | C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO ECC Certification Authority | 2038-Jan-18 | 1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7 |
| `comodo-rsa-certification-authority.der` | C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO RSA Certification Authority | 2038-Jan-18 | 52f0e1c4e58ec629291b60317f074671b85d7ea80d5b07273463534b32b40234 |
| `digicert-global-root-g2.der` | C=US,O=DigiCert Inc,OU=www.digicert.com,CN=DigiCert Global Root G2 | 2038-Jan-15 | cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f |
| `digicert-global-root-g3.der` | C=US,O=DigiCert Inc,OU=www.digicert.com,CN=DigiCert Global Root G3 | 2038-Jan-15 | 31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0 |
| `digicert-tls-ecc-p384-root-g5.der` | C=US,O=DigiCert, Inc.,CN=DigiCert TLS ECC P384 Root G5 | 2046-Jan-14 | 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05 |
| `digicert-tls-rsa4096-root-g5.der` | C=US,O=DigiCert, Inc.,CN=DigiCert TLS RSA4096 Root G5 | 2046-Jan-14 | 371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75 |
| `globalsign-ecc-root-ca-r5.der` | OU=GlobalSign ECC Root CA - R5,O=GlobalSign,CN=GlobalSign | 2038-Jan-19 | 179fbc148a3dd00fd24ea13458cc43bfa7f59c8182d783a513f6ebec100c8924 |
| `globalsign-root-ca-r3.der` | OU=GlobalSign Root CA - R3,O=GlobalSign,CN=GlobalSign | 2029-Mar-18 | cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b |
| `globalsign-root-ca-r6.der` | OU=GlobalSign Root CA - R6,O=GlobalSign,CN=GlobalSign | 2034-Dec-10 | 2cabeafe37d06ca22aba7391c0033d25982952c453647349763a3ab5ad6ccf69 |
| `globalsign-root-e46.der` | C=BE,O=GlobalSign nv-sa,CN=GlobalSign Root E46 | 2046-Mar-20 | cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058 |
| `globalsign-root-r46.der` | C=BE,O=GlobalSign nv-sa,CN=GlobalSign Root R46 | 2046-Mar-20 | 4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9 |
| `go-daddy-root-certificate-authority-g2.der` | C=US,ST=Arizona,L=Scottsdale,O=GoDaddy.com, Inc.,CN=Go Daddy Root Certificate Authority - G2 | 2037-Dec-31 | 45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda |
| `gts-root-r1.der` | C=US,O=Google Trust Services LLC,CN=GTS Root R1 | 2036-Jun-22 | d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf |
| `gts-root-r3.der` | C=US,O=Google Trust Services LLC,CN=GTS Root R3 | 2036-Jun-22 | 34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48 |
| `gts-root-r4.der` | C=US,O=Google Trust Services LLC,CN=GTS Root R4 | 2036-Jun-22 | 349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d |
| `isrg-root-x1.der` | C=US,O=Internet Security Research Group,CN=ISRG Root X1 | 2035-Jun-4 | 96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6 |
| `isrg-root-x2.der` | C=US,O=Internet Security Research Group,CN=ISRG Root X2 | 2040-Sep-17 | 69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470 |
| `microsoft-ecc-root-certificate-authority-2017.der` | C=US,O=Microsoft Corporation,CN=Microsoft ECC Root Certificate Authority 2017 | 2042-Jul-18 | 358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02 |
| `microsoft-rsa-root-certificate-authority-2017.der` | C=US,O=Microsoft Corporation,CN=Microsoft RSA Root Certificate Authority 2017 | 2042-Jul-18 | c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0 |
| `sectigo-public-server-authentication-root-e46.der` | C=GB,O=Sectigo Limited,CN=Sectigo Public Server Authentication Root E46 | 2046-Mar-21 | c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383 |
| `sectigo-public-server-authentication-root-r46.der` | C=GB,O=Sectigo Limited,CN=Sectigo Public Server Authentication Root R46 | 2046-Mar-21 | 7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06 |
| `ssl-com-tls-ecc-root-ca-2022.der` | C=US,O=SSL Corporation,CN=SSL.com TLS ECC Root CA 2022 | 2046-Aug-19 | c32ffd9f46f936d16c3673990959434b9ad60aafbb9e7cf33654f144cc1ba143 |
| `ssl-com-tls-rsa-root-ca-2022.der` | C=US,O=SSL Corporation,CN=SSL.com TLS RSA Root CA 2022 | 2046-Aug-19 | 8faf7d2e2cb4709bb8e0b33666bf75a5dd45b5de480f8ea8d4bfe6bebc17f2ed |
| `starfield-root-certificate-authority-g2.der` | C=US,ST=Arizona,L=Scottsdale,O=Starfield Technologies, Inc.,CN=Starfield Root Certificate Authority - G2 | 2037-Dec-31 | 2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5 |
| `starfield-services-root-certificate-authority-g2.der` | C=US,ST=Arizona,L=Scottsdale,O=Starfield Technologies, Inc.,CN=Starfield Services Root Certificate Authority - G2 | 2037-Dec-31 | 568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5 |
| `usertrust-ecc-certification-authority.der` | C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust ECC Certification Authority | 2038-Jan-18 | 4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a |
| `usertrust-rsa-certification-authority.der` | C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority | 2038-Jan-18 | e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2 |
