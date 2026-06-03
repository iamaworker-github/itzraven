---
name: saml-attacks
description: SAML attacks — assertion manipulation, XML signature wrapping, response tampering, certificate faking
category: vulnerabilities
---

# SAML Attack Methodology

## SAML Message Structure
```
<samlp:Response>
  <saml:Assertion>
    <saml:Subject><saml:NameIdentifier>user@domain.com</saml:NameIdentifier></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role"><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
    <saml:AuthnStatement><saml:SubjectLocality IPAddress="192.168.1.1"/></saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```

## Signature Wrapping
- XML Signature only covers specific elements
- Inject duplicate elements outside the signed portion
- Service provider may use the unsigned element instead
```
<Assertion ID="signed_assertion">
  <Signature>...</Signature>
  <Subject>victim@target.com</Subject>  ← signed
</Assertion>
<Assertion ID="fake_assertion">
  <Subject>attacker@target.com</Subject>   ← not signed, but parsed
</Assertion>
```

## Response Tampering
- Change `NameIdentifier` to another user → authenticate as target
- Change `AttributeValue` (Role) to `admin` → privilege escalation
- Modify `NotBefore`/`NotOnOrAfter` → replay attacks
- Remove or nullify `Destination` attribute

## Certificate / Key Confusion
- Remove `<Signature>` entirely → some SPs don't enforce
- Include self-signed certificate in `<KeyInfo>` → SP may trust it
- Change cert reference to attacker-controlled URL

## Replay Attack
1. Capture valid SAML response (via proxy)
2. Replay it to the service provider
3. If no `AssertionID` tracking or timestamp validation → login as victim

## Common Vulnerabilities
- No signature validation → tamper any field
- No audience restriction → use assertion on different SP
- Weak certificate (self-signed, expired, SHA-1)
- XML entity expansion (XXE) in SAML XML
- No `NotOnOrAfter` timestamp → token never expires

## Tools
- `SAML Raider` (Burp extension)
- `samltool.io` — decode/encode/forge SAML
- Python `python3-saml` with manual XML manipulation
