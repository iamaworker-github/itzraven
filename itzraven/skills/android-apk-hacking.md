---
name: android-apk-hacking
description: Android APK bug bounty — decompilation, static analysis, exported components, deep links, Frida, SSL pinning bypass
category: mobile
---

# Android APK Bug Bounty Methodology

> For authorized bug bounty programs with Android apps in scope.

## PHASE 1 — Reconnaissance
```bash
# Gather info about the app
grep -r "SECRET\|PASSWORD\|API_KEY\|TOKEN" output/ --include="*.java" -i
grep -r "http://" output/ --include="*.java"
grep -r "MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE" output/ --include="*.java"
grep -r "getSharedPreferences\|openFileOutput" output/ --include="*.java"
```

## PHASE 2 — Static Analysis
```bash
# Decompile APK
jadx -d output/ base.apk

# Check manifest for exported components
cat output/resources/AndroidManifest.xml | grep 'exported="true"'

# Find deep links / intent filters
grep -r "android:scheme\|android:host\|android:pathPattern" output/ --include="*.xml"
```

### Exported Component Checklist
- **Activities**: `exported="true"` — can be launched externally
- **Services**: `exported="true"` — can be bound by other apps
- **Content Providers**: `exported="true"` — data access via URI
- **Broadcast Receivers**: `exported="true"` — can receive malicious intents

## PHASE 3 — Dynamic Analysis
```bash
# Test exported activities
adb shell am start -n com.target.app/.ExportedActivity

# ContentProvider testing (SQLi / IDOR)
adb shell content query --uri content://com.target.provider/users
adb shell content query --uri "content://com.target.provider/users' OR '1'='1"

# Deep link testing
adb shell am start -W -a android.intent.action.VIEW -d "targetapp://settings" com.target.app

# Broadcast receiver testing
adb shell am broadcast -a com.target.CUSTOM_ACTION --es extra_key "malicious"
```

## PHASE 4 — SSL Pinning Bypass
```bash
# Frida script for universal SSL bypass
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# Objection runtime
objection -g com.target.app explore
```

## PHASE 5 — API Security Testing
- Capture all traffic via Burp Suite (after SSL bypass)
- Map every API endpoint: auth, user data, payments, admin
- Test IDOR, BOLA, mass assignment on captured endpoints
- Check JWT handling and session management

## PHASE 6 — WebView Testing
- Check exposed JavaScript interfaces: `addJavascriptInterface`
- Test WebView file access: `setAllowFileAccess(true)`
- Test arbitrary URL loading in WebViews
- Check for XSS via deep links loading into WebViews

## PHASE 7 — Business Logic
- Race conditions via simultaneous requests
- Negative quantity / amount values
- Step-skipping in multi-step flows
- Coupon/promotion abuse

## Tools
- **jadx** — `jadx -d output/ target.apk`
- **apktool** — `apktool d target.apk`
- **Frida** — Dynamic instrumentation + SSL bypass
- **Objection** — Runtime mobile exploration
- **Burp Suite** — API traffic interception
