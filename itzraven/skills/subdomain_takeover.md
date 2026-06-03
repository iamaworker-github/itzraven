---
name: subdomain_takeover
description: Dangling DNS records, cloud resource claims, takeover verification
category: vulnerabilities
---

# Subdomain Takeover Testing

## Attack Surface
Subdomain takeover occurs when a DNS record points to a service that the domain owner no longer controls.
- AWS S3 buckets / CloudFront distributions
- Azure services (App Service, CDN, Traffic Manager)
- GitHub Pages
- Heroku, Netlify, Vercel, Shopify
- AWS Elastic Beanstalk
- Third-party services (Zendesk, Freshdesk, Intercom)

## Methodology
1. **Detection**
   - Scan for CNAME records pointing to external services
   - Check DNS resolution: NXDOMAIN for claimed CNAME targets
   - Verify service no longer exists at the CNAME target
   - Use fingerprint: specific error pages per service type

2. **Fingerprints by Provider**
   - AWS S3: `NoSuchBucket` error
   - Azure: `404 Not Found` with specific error
   - GitHub Pages: `404 - File not found`
   - Heroku: `No such app`
   - Shopify: `Sorry, this shop is currently unavailable`

3. **Exploitation**
   - Register the claimed resource on the cloud provider
   - Host content on the claimed service
   - Verify takeover by accessing the subdomain
   - Demonstrate impact: cookie theft, phishing page

## Validation
- DNS CNAME confirmed pointing to unclaimed service
- Resource successfully registered
- Content served from taken-over subdomain
- SSL/TLS valid for the subdomain
