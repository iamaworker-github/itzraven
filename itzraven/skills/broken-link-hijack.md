---
name: broken-link-hijack
description: Broken link hijacking methodology — finding and exploiting dead external links for account takeover
category: vulnerabilities
---

# Broken Link Hijacking Methodology

## Discovery
1. **Manual**: Click all external links on target site (social media, CDN references, partner sites)
2. **Automated**: Use broken-link-checker tools, crawl for external href/src attributes
3. **Sources to check**:
   - Social media icons (Twitter, LinkedIn, Facebook, YouTube)
   - Profile/author links in blog posts
   - External image/media URLs
   - Script/src references to CDN or analytics
   - Partner/customer logos with links
   - Footer attribution links
   - Documentation/README external references

## Registration
- Register accounts on the external platform
- If the external link references a social media profile
- Create a profile matching the expected username
- If it references a custom domain, purchase the expired domain

## Exploitation
- Any user clicking the broken link will now land on attacker-controlled page
- Set up identical page with tracking/analytics to steal session cookies
- Use for phishing campaigns (clone login page)
- Combine with other vulnerabilities for account takeover

## Impact Chain
- Session cookie theft via same-origin redirects
- CSRF token theft via referer leakage
- Account takeover via credential harvesting
- Reputation damage via malicious redirects

## Prevention Checklist
- Use relative URLs for internal resources
- Regularly audit and update external links
- Use link shorteners with ownership control
- Implement CSP to restrict external content
- Monitor for 404 external references
