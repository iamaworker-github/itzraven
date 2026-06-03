# NestJS Security Skill

Specialized security analysis for NestJS applications.

## Detection Rules

### Guards & Authorization
- `@UseGuards()` missing on critical endpoints
- `@Roles()` decorator bypass paths
- Hardcoded role checks in controllers
- Missing CSRF protection on mutating endpoints

### Input Validation
- Missing `ValidationPipe` or `class-validator` decorators
- Raw `@Body()` without DTO
- `@Query()` / `@Param()` without type validation
- GraphQL `@Args()` without validation

### ORM / Database
- Raw SQL queries via `@InjectRepository()` + `query()`
- Missing `@Transaction()` on multi-step writes
- N+1 query patterns in resolvers/controllers
- Unsafe `find()` without pagination or limits

### Dependency Injection
- Provider with `@Injectable()` exposing secrets or tokens
- Circular dependency patterns
- Dynamic module imports with user-controlled paths

### Middleware
- Missing helmet/cors configuration in `main.ts`
- Rate-limiting bypass through public routes
- Body parser size limits too large

## Scan Overrides
```
--skill nestjs --scope "**/*.ts" --exclude "**/*.spec.ts"
```

## Priority Weights
- Missing Guards: critical
- Raw SQL: critical
- Missing ValidationPipe: high
- Unsafe find(): medium
- DI leaks: high
- Middleware misconfig: medium
