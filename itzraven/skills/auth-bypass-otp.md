---
name: auth-bypass-otp
description: Authentication bypass via OTP manipulation, response tampering, and verification logic flaws
category: vulnerabilities
---

# Authentication Bypass via OTP Manipulation

## Response Manipulation
1. Register/login with a valid mobile number
2. Enter correct OTP, intercept the success response
3. Register a new account with attacker's number
4. Enter wrong OTP, intercept the failure response
5. Replace failure response with the captured success response
6. If server trusts client-side response → bypass

## OTP Brute Force
- 4-digit OTP = only 10000 combinations
- 6-digit OTP = 1M combinations (harder but possible without rate limit)
- Check rate limiting specifically on OTP validation endpoint
- Bypass rate limits via headers (X-Forwarded-For rotation)
- Try parallel requests (race condition on OTP validation)

## OTP Leakage
- Check if OTP is returned in API response (even when wrong)
- Look for OTP in response headers, cookies
- Check WebSocket messages during OTP flow
- Inspect error messages that reveal OTP length/portion
- Check browser console for debug logging of OTP

## Business Logic Flaws
- Skip OTP step entirely (direct navigation to post-OTP URL)
- Modify step parameter in request (step=2 instead of step=1)
- Remove OTP field from request
- Send empty OTP value
- Send OTP array instead of string: `otp[]=1&otp[]=2&otp[]=3&otp[]=4`
- Register via different flow that doesn't require OTP
- Use OTP from another active session

## Token Reuse
- Complete OTP flow, obtain auth token
- Logout
- Try reusing the same OTP for a new registration
- Check if OTP is single-use or multi-use

---

## 2FA Bypass Techniques (Expanded)

### SMS/Call Interception
- SIM swap → attacker receives SMS OTP
- SS7 vulnerability → intercept SMS messages
- Call forwarding → redirect voice OTP
- Voicemail interception → OTP left as voicemail

### Backup Code Abuse
- Backup codes often have no rate limiting
- 10 backup codes = only 10 guesses
- Check if backup codes are stored insecurely (profile page, email)
- Regenerate backup codes doesn't invalidate old ones (reuse)

### Biometric Bypass
- Test fingerprint sensor with gelatin/cut latex
- Test face recognition with photo/video (liveness check bypass)
- Check if biometric falls back to PIN/password after N failures
- Test biometric in different lighting conditions

### OTP Channel Switching
- Request OTP via SMS instead of authenticator app
- Request OTP via email instead of SMS
- Request OTP via voice call instead of SMS
- Some channels have weaker validation

### Time-Based (TOTP) Attacks
- Clock skew: set device time wrong → reused old TOTP
- TOTP seed stored insecurely (localStorage, cookie)
- QR code reuse during enrollment
- Check if TOTP uses weak hash (MD5, SHA-1)
- TOTP validity window > 30 seconds

### Push Notification Bypass
- Deny push → try again → multiple push notifications
- MFA fatigue: spam push notifications until user accepts
- Check if push approval reveals IP/location that can be spoofed
- Test with expired session for push approval

### Hardware Token Attacks
- CR0065 token extraction (physical access)
- RFID cloning for NFC-based tokens
- YubiKey static password extraction
- Token serial number enumeration (some tokens derived from serial)

