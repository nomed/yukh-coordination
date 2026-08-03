# Relay runtime composition

This internal package implements the accepted RFC-0007 composition and
lifecycle boundary. It assembles the qualified HTTP/SSE, application, signing,
Store and notification layers from explicit typed dependencies.

It does not select products, read external configuration, provide identity or
ACL policy, load signing keys, expose operational routes or authorize a process
binary. Those concerns require an accepted provider profile.

Successful construction transfers the supplied listener and named resources
to the runtime. The caller must invoke `Run` exactly once; `Run` is the sole
lifecycle entry point and always performs bounded shutdown and cleanup. Owned
resource closers receive a shared cleanup context and must honor its deadline.
