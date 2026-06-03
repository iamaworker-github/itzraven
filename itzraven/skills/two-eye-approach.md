---
name: two-eye-approach
description: The Two-Eye Approach — systematic coverage + curiosity-driven investigation for finding critical bugs scanners miss
category: methodology
---

# The Two-Eye Approach

> The single most important mindset shift between hunters who find medium bugs and hunters who find critical ones.

```
┌─────────────────────────────────────────────────────────────┐
│                    TWO-EYE APPROACH                          │
│                                                              │
│  FIRST EYE — Systematic Coverage                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Go through EVERY subdomain, EVERY endpoint,          │   │
│  │ EVERY parameter systematically.                      │   │
│  │ Run every tool. Complete the checklist.              │   │
│  │ No skipping. Methodical. Thorough.                   │   │
│  └──────────────────────────────────────────────────────┘   │
│           ↓                                                  │
│  SECOND EYE — Curiosity-Driven Investigation                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Step back from the checklist.                        │   │
│  │ Look for what's UNUSUAL:                             │   │
│  │ • Subdomains with odd naming patterns                │   │
│  │ • Endpoints returning different response sizes       │   │
│  │ • Parameters behaving differently than neighbors     │   │
│  │ • Admin panels that shouldn't be indexed             │   │
│  │ • S3 buckets named after internal projects           │   │
│  │ • Error messages leaking stack traces                │   │
│  │ • Inconsistent auth enforcement                      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## First Eye — Systematic Coverage
Cover every asset thoroughly:
- Every subdomain gets HTTP probed, technology fingerprinted
- Every live endpoint gets checked for common vulns
- Every parameter gets tested for injection
- Run the full tool pipeline on everything
- No skipping because "it looks boring"

## Second Eye — Curiosity-Driven Investigation
Step back and look for what's unusual. The second eye is not a tool — it's a mindset developed over hundreds of hours of hunting.

### What to Look For
- **Odd naming patterns**: `dev-internal.target.com`, `test-api-2.target.com`
- **Response size anomalies**: One endpoint returns 10x more data than similar endpoints
- **Parameter behavior differences**: One parameter crashes, another doesn't
- **Admin panels indexed by search engines**
- **S3 buckets with internal project names**
- **Stack traces in error messages**
- **Auth inconsistencies**: One endpoint requires auth, similar one doesn't

## Decision Tree
```
Found something interesting?
    ↓
YES →
  1. Document exactly what you found and how
  2. Test full impact (can you escalate? pivot? exfiltrate?)
  3. Create POC
  4. Report
    ↓
NO →
  1. Pivot to unusual subdomains / unique endpoints
  2. Check for business logic issues
  3. Review JS files for undocumented APIs
  4. Manually browse app as different user roles
  5. Check Wayback for recently added features
```

## First Pass Checklist
- [ ] All subdomains probed with httpx
- [ ] All live hosts scanned with nuclei (critical/high)
- [ ] All URLs filtered by gf patterns
- [ ] All JS files fetched and analyzed
- [ ] All parameters tested for injection
- [ ] All API endpoints checked for IDOR
- [ ] All forms tested for XSS/CSRF
- [ ] All auth flows tested for bypass

## Second Pass Checklist
- [ ] Response size comparison across similar endpoints
- [ ] Error message content analysis
- [ ] Auth enforcement inconsistency check
- [ ] Wayback diff for recent changes
- [ ] Unusual subdomain investigation
- [ ] Business logic workflow analysis
