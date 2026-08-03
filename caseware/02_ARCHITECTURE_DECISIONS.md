# Architectural Decisions Record (ADR)

## 1. Caching Strategy for Authorization (Use Case 2)
- **Constraint:** Must handle tens of thousands of authorization checks per second.
- **Decision:** Implement a two-tier caching strategy (L1/L2). 
  - L1: In-Memory Cache on the API instance (1-2 second TTL).
  - L2: Distributed Redis Cluster caching user permission snapshots and a `perm_epoch` integer.
- **Revocation:** Event-driven. When permissions change, invalidate the Redis key, increment the `perm_epoch`, and publish an event to drop active WebSockets.

## 2. On-Behalf-Of Delegation (Use Case 3)
- **Constraint:** Prevent the "Confused Deputy" problem.
- **Decision:** Use standard OAuth 2.0 Token Exchange (RFC 8693).
- **Implementation:** The endpoint will accept a `subject_token` and `actor_token`, and issue a Downstream Token containing an `act` (Actor) claim detailing the intermediary service, while preserving the original `sub`.
