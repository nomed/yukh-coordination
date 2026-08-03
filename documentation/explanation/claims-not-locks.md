# Claims are not locks

A claim says that a participant has asserted responsibility for work. It does
not reserve a resource or prove permission.

Concurrent claims remain visible as a conflict. Disconnection, session expiry
or silence does not release a claim. A handoff transfers protocol-observable
state only after the exact recipient accepts the current offer and creates the
successor claim.

Repositories, project policy or another authority still decide whether the
participant may perform the work.
