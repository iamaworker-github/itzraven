---
name: session-management
description: Session management vulnerabilities — session fixation, concurrent sessions, predictable tokens, expiry issues
category: vulnerabilities
---

# Session Management Bug Methodology

## Old Session Persistence
1. Login to application
2. Note session token
3. Logout
4. Try reusing old session token
5. If still valid → session not properly invalidated on logout

## Session Fixation
1. Obtain valid session token before login
2. Force this session onto victim (via URL parameter, cookie injection)
3. Victim logs in
4. Attacker now has authenticated session

## Concurrent Session Issues
- Login from multiple devices/browsers simultaneously
- Check if old sessions are properly invalidated
- Try password change while another session is active
- Check if admin can terminate specific sessions

## Predictable Session Tokens
1. Collect multiple session tokens sequentially
2. Analyze pattern (timestamp, incremental ID, hash of known values)
3. If pattern found, predict other users' tokens
4. Increment/decrement token value to find adjacent sessions

## Token Exposure Vectors
- Session in URL: `?session=abc123` → leaks via Referer
- Session in browser history
- Session in server logs/analytics
- Session in JSON/API responses
- Clear text transmission over HTTP

## Timeout Issues
- No idle timeout → session never expires
- Long absolute timeout (>24 hours)
- No timeout on remember-me tokens
- Remember-me token bypasses all security controls
- Token doesn't rotate on privilege escalation

## Logout Issues
- Logout only removes client-side cookie
- Backend session remains active
- Multiple logouts required (no single sign-out)
- Admin force-logout not propagated to user sessions
