# Requiring client certificates

`server.tls.ca_file` turns on mutual TLS. A client must then present a
certificate the bundle signs, on both the HTTP and the gRPC listener.

```yaml
server:
  tls:
    enabled: true
    cert_file: /etc/agentmon/tls/server.crt
    key_file: /etc/agentmon/tls/server.key
    ca_file: /etc/agentmon/tls/clients-ca.crt
```

Without `ca_file` the behaviour is unchanged: TLS, and the client proves
nothing.

## The field existed and configured nothing

`ServerTLSConfig.CAFile` has been in the schema for a long time. Nothing read
it. The two listeners built their own TLS configs, the HTTP one from
`tls.LoadX509KeyPair` and the gRPC one from
`credentials.NewServerTLSFromFile`, and neither has a way to express client
verification at all. The shipped `config.yml` also carried
`client_auth: false`, which is not a field in the schema and was parsed into
nothing.

Both listeners now go through `serverTLSConfig`. One builder is what stops them
drifting again: mutual TLS on the HTTP port and one-way on the gRPC port is not
a configuration anyone would choose deliberately.

## RequireAndVerifyClientCert

Go offers four other `ClientAuth` values. Two of them, `RequestClientCert` and
`VerifyClientCertIfGiven`, accept a client that presents no certificate, which
is every client an attacker controls. `RequireAndVerifyClientCert` is the only
one that means what `ca_file` reads as.

The pool holds exactly the certificates in `ca_file`, never the system roots.
Seeding from the system store would let any publicly issued certificate
authenticate, and no rejection test catches that, because a test CA is not in
the system store either.

Three failures are refused at startup rather than at handshake time:

- `ca_file` with `enabled: false`. Honouring it on a plaintext listener is
  impossible, so ignoring it would authenticate nothing while looking like it
  authenticated everything.
- `ca_file` that cannot be read. Ignoring the read error also fails, on the
  empty pool, but reports "contains no certificates" and sends the operator
  looking at the file's contents rather than at its path.
- `ca_file` that parses to no certificates. The pool would verify nothing, so
  every client is rejected and the operator debugs handshakes rather than a
  typo.

`agentmon config validate` catches the first before deploy.

## Testing this is not just a handshake

Under TLS 1.3 the client finishes its handshake before the server has verified
the client certificate. The rejection arrives as an alert on the first record.
A test that only calls `Handshake()` passes against a server doing no client
verification at all, so `internal/server/tls_test.go` completes a round trip.

## What this does not do

**The client certificate is not an identity.** It gates the connection; the
API key or OIDC token still authorises the request. Mapping a certificate
subject to a principal would be a second authentication scheme, and the
interceptors do not read one.

**The loopback rule is unchanged.** `auth.type=none` on a non-loopback address
is still refused, even under mutual TLS. A client certificate is arguably
authentication, so the check could be relaxed, but a `ca_file` pointed at a
public CA bundle would then let any publicly issued certificate onto the API.
Relaxing a fail-closed check is a deliberate decision, not a side effect of
adding one.

## Connecting to it

The CLI reads the same material through five persistent flags, each with an
`AGENTMON_*` environment default:

```
agentmon --server https://daemon:18080 \
  --tls-ca /etc/agentmon/tls/ca.crt \
  --tls-cert ~/.agentmon/client.crt \
  --tls-key ~/.agentmon/client.key \
  session list
```

`--transport grpc` uses the same flags for the gRPC dial. `--tls` alone turns
TLS on for gRPC against a server whose certificate the system roots already
trust; any other `--tls-*` flag implies it. `--tls-server-name` overrides the
name checked against the certificate, for connecting by IP.
`--tls-insecure-skip-verify` disables verification.

Two mismatches are refused rather than ignored. TLS flags with an `http://`
server URL is an error, because attaching a `tls.Config` to an `http://`
client does nothing and the request would go out in the clear while the
operator believed `--tls-ca` had been honoured. TLS flags with a `unix://`
socket is an error for the same reason. Over `--transport grpc` an `http://`
base URL is fine: the flags belong to the gRPC leg, and the HTTP one carries
only the endpoints gRPC does not.
