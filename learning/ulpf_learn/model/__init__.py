"""P4 — the model provider. A locally served model (llama.cpp) proposes semantics for an induced
structure under token-level grammar constraint; every output is validated against the emission schema
and checked for type compatibility against the validator's enumeration before it becomes a Proposal.
The model never sees a live log (invariant 2) and never emits code (invariant 1): it emits labels."""
