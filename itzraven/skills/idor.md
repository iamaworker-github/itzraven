---
name: idor
description: Object reference attacks, horizontal/vertical privilege escalation
category: vulnerabilities
---

# IDOR Testing

## Attack Surface
IDOR occurs when an application exposes direct object references without proper authorization.
- Numeric IDs: `/users/1`, `/orders/1002`
- UUIDs: `/api/invoices/550e8400-e29b-41d4`
- File paths: `/download?file=report_2024.pdf`
- Endpoint access without authentication

## Methodology
1. **Pattern Discovery**
   - Look for sequential IDs in URLs and API responses
   - Check for object references in JSON responses
   - Examine JavaScript files for API endpoints with IDs
   - Use HTTP archive (HAR) files from authenticated sessions

2. **Horizontal Privilege Escalation**
   - Change ID to access another user's data: `/users/1` -> `/users/2`
   - Try negative IDs: `/users/-1`
   - Try array/object injection: `/users/[]`
   - Use mass assignment: `{"user_id": 2, "role": "admin"}`

3. **Vertical Privilege Escalation**
   - Access admin endpoints as regular user: `/admin/users`
   - Try HTTP method override: `GET /admin` -> `POST /admin` with `X-HTTP-Method-Override: GET`
   - Check for unguarded API endpoints in JS files

## Validation
- Confirm access to another user's private data
- Verify ability to modify/delete another user's resources
- Check if response differs between authorized and unauthorized access attempts
- Automated tooling can confirm via consistent response patterns
