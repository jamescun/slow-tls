# SlowTLS

SlowTLS artificially slows Go TLS negotiation the closer a certificate gets to its expiry.

Inspired by a [tweet](https://twitter.com/matthew_d_green/status/1225423229151514625) by Matthew Green.


## Example

```go
cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")

config := &tls.Config{
	Certificates: []tls.Certificate{cert},
}

// delay the TLS negotiation by up to 5 minutes for 24 hours before the
// certificate expires.
slowtls.SlowTLS(config, 24 * time.Hour, 5 * time.Minute)

s := &http.Server{
	Addr:      ":8080",
	TLSConfig: config,
}

s.ListenAndServeTLS("", "")
```
