---
name: graphql
description: GraphQL introspection, batching, resolver injection
category: protocols
---

# GraphQL Security Testing

## Attack Surface
GraphQL APIs expose a flexible query interface that can be abused in unique ways.
- Introspection queries exposing entire schema
- Batching attacks (query batching for auth bypass)
- N+1 query attacks (deeply nested queries for DoS)
- Direct steal: batch multiple login attempts
- Field suggestions revealing hidden endpoints

## Methodology
1. **Schema Discovery**
   - Query `__schema` for full schema introspection
   - Use `__type` for detailed type information
   - Check for suggestions mode (typo-friendly field names)

2. **Authorization Testing**
   - Query fields that should be restricted
   - Batch multiple operations with different auth contexts
   - Test mutations without proper authorization
   - Check if field-level authorization is enforced

3. **Injection Testing**
   - SQL injection in GraphQL arguments
   - NoSQL injection in GraphQL resolvers
   - Command injection through resolver inputs
   - Batching: use aliases to bypass rate limits

4. **Rate Limiting & Abuse**
   - Test for query cost analysis (deep nested queries)
   - Check rate limiting on mutations
   - Introspection persistence after disabling
   - Batched queries for credential stuffing

## Validation
- Schema retrieved via introspection
- Unauthorized access to restricted fields
- Successful injection through resolver
- Rate limit bypassed via batched queries
