// EXPECTED_FINDINGS: [{"primitive":"SHA1","category":"hash","line":4},{"primitive":"RSA","category":"asymmetric-cipher","line":5},{"primitive":"AES","category":"symmetric-cipher","line":6,"keySizeBits":256},{"primitive":"TLSv1.2","category":"protocol","line":14}]
package main
import (
    "crypto/sha1"
    "crypto/rsa"
    "crypto/aes"
    "crypto/tls"
)
_ = sha1.New
_ = rsa.GenerateKey
_ = aes.NewCipher

func serverTLS() *tls.Config {
    return &tls.Config{MinVersion: tls.VersionTLS12}
}
