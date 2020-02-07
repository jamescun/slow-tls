package slowtls

import (
	"crypto/tls"
	"math/rand"
	"time"
)

// SlowTLS modifies a TLS Config to artificially introduce a delay in TLS
// negotiation the closer a certificate gets to expiry.
//
// Inspired by this tweet: https://twitter.com/matthew_d_green/status/1225423229151514625
func SlowTLS(cfg *tls.Config, periodBeforeExpiry, maximumDelay time.Duration) {
	originalGetCertificate := cfg.GetCertificate

	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var cert *tls.Certificate

		// resolve certificate from function
		if originalGetCertificate != nil {
			var err error
			cert, err = originalGetCertificate(hello)
			if err != nil {
				return nil, err
			}
		}

		// resolve certificate from name map
		if cert == nil && cfg.NameToCertificate != nil {
			cert = cfg.NameToCertificate[hello.ServerName]
		}

		// resolve first certificate from array
		if cert == nil && len(cfg.Certificates) > 0 {
			cert = &cfg.Certificates[0]
		}

		// couldn't resolve a certificate from any mechanism
		if cert == nil {
			return nil, nil
		}

		if cert.Leaf != nil {
			if cert.Leaf.NotBefore.Sub(time.Now()) > periodBeforeExpiry {
				// TODO(jc): increase delay proportional to time before expiry
				delay := time.Duration(rand.Int63n(int64(maximumDelay)))
				time.Sleep(delay)
			}
		}

		return cert, nil
	}
}
