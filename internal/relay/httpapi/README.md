# HTTP/SSE edge

This package implements the accepted RFC-0004 transport boundary. It contains
no identity provider, policy engine, database or signer.

The handler owns only transport responsibilities:

- strict versioned route, media-type, framing and cursor parsing;
- TLS and Bearer-token extraction;
- authentication before tenant derivation;
- authorization before application or resource lookup;
- non-enumerating denial and bounded Problem Details;
- append outcome mapping without unsigned success;
- ordered SSE formatting, cursor discipline, revocation signal, heartbeat,
  write deadline and maximum connection lifetime.

`Authenticator`, `Authorizer` and `Application` are provider-neutral ports.
Forwarded identity headers and client-supplied tenant values are never read.
The application port must validate canonical protocol bytes, build signed
receipts, produce bounded replay pages and provide a race-free replay-to-live
stream. Those behaviors are not inferred by the HTTP layer.

No server executable or public deployment is authorized by this package.
