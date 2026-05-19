# Security and Legal

Responsible use guidelines and legal considerations for CyberMind CLI.

---

## Table of Contents

- [Authorized Use Only](#authorized-use-only)
- [Responsible Disclosure](#responsible-disclosure)
- [Legal Compliance](#legal-compliance)
- [Data Privacy](#data-privacy)
- [Terms of Service](#terms-of-service)
- [Reporting Misuse](#reporting-misuse)

---

## Authorized Use Only

**You must have explicit written permission to test any target.**

### Authorized Scenarios

✅ **You own the target** — Your own servers, applications, domains
✅ **Written permission** — Client contract, bug bounty program, authorization letter
✅ **Public bug bounty** — Testing within program scope on HackerOne, Bugcrowd, etc.
✅ **Educational labs** - Hack The Box, TryHackMe, VulnHub, your own lab
✅ **CTF competitions** - Within competition rules

### Unauthorized Scenarios

❌ **Without permission** — Testing random websites, servers, organizations
❌ **Outside scope** — Testing beyond bug bounty program rules
❌ **Malicious intent** — Using for data theft, disruption, harassment
❌ **Government targets** — Testing government systems without authorization
❌ **Critical infrastructure** — Testing hospitals, power grids, emergency services

**Unauthorized use is illegal and violates our Terms of Service.**

---

## Responsible Disclosure

### If You Find a Vulnerability

1. **Stop immediately** — Do not exploit further
2. **Document** — Take screenshots, save evidence
3. **Report** — Follow the program's disclosure policy
4. **Cooperate** — Work with the vendor on fix timeline
5. **Public disclosure** — Only after vendor fixes and approves

### Disclosure Timeline

| Phase | Timeframe |
|---|---|
| Initial report | Immediately |
| Vendor acknowledgment | 48 hours |
| Fix timeline | 30-90 days (depends on severity) |
| Public disclosure | After fix deployed |

### HackerOne/Bugcrowd Programs

Always follow the specific program's rules:
- Scope (what you can/cannot test)
- Testing methods (allowed tools)
- Out-of-scope (what to avoid)
- Disclosure policy

---

## Legal Compliance

### Computer Fraud and Abuse Act (CFAA) - USA

Unauthorized access to computer systems is a federal crime.

### Computer Misuse Act (CMA) - UK

Unauthorized access, intent to impair, or unauthorized modification is illegal.

### IT Act - India

Section 66: Computer-related offenses (hacking, unauthorized access).

### GDPR - EU

Data protection law. Testing without consent violates data privacy rights.

### Your Responsibility

- Know your local laws
- Get written authorization
- Stay within legal boundaries
- Follow responsible disclosure

---

## Data Privacy

### What CyberMind Collects

- API key (hashed in database)
- Usage logs (endpoint, timestamp, status)
- Error logs (no sensitive data)

### What CyberMind Does NOT Collect

- Tool output from your scans
- Target URLs/domains
- Your findings/vulnerabilities
- Personal data from targets

### Data Storage

- Database: Supabase PostgreSQL (encrypted at rest)
- Logs: Retained for 90 days
- API keys: SHA-256 hashed

### Data Deletion

```bash
# Request deletion
support@cybermindcli.com
```

---

## Terms of Service

By using CyberMind, you agree to:

1. **Authorized Use Only**
   - Only test targets you own or have written permission to test

2. **No Illegal Activity**
   - Not use for hacking, data theft, harassment, or any illegal purpose

3. **Responsible Disclosure**
   - Follow responsible disclosure practices for vulnerabilities found

4. **Indemnification**
   - You are solely responsible for your use of CyberMind

5. **No Warranty**
   - CyberMind is provided "as is" without warranties

6. **Plan Limits**
   - Respect rate limits and plan restrictions

7. **API Key Security**
   - Keep your API key secret, do not share

---

## Reporting Misuse

### If You Observe Misuse

If you believe CyberMind is being used illegally:

1. **Document evidence** — Screenshots, logs, timestamps
2. **Report to us** — abuse@cybermindcli.com
3. **Report to authorities** — If illegal activity, contact law enforcement
4. **We will investigate** — Suspend accounts violating ToS

### Incident Response Process

1. Receive abuse report
2. Verify evidence
3. Suspend offending account
4. Cooperate with authorities
5. Prevent future abuse

---

## Security Best Practices

### For Bug Bounty Hunters

- **Stay in scope** — Read program rules carefully
- **No destructive testing** — Don't delete data, disrupt services
- **Rate limit** — Don't overwhelm targets
- **Report promptly** — Submit findings quickly
- **Be professional** — Communicate respectfully with triage

### For Penetration Testers

- **Written contract** — Always get written scope
- **Define rules** — Clear what's in/out of scope
- **Regular check-ins** — Update client on progress
- **No data exfiltration** — Unless explicitly authorized
- **Clean up** - Remove any backdoors/implants after test

### For Security Researchers

- **Responsible disclosure** — Give vendors time to fix
- **Proof of concept** — Demonstrate without causing harm
- **Collaborate** — Work with vendors on fixes
- **Credit** — Acknowledge vendor cooperation
- **Learn** - Share knowledge responsibly

---

## Disclaimer

CyberMind is a tool for authorized security testing only. The creators are not responsible for misuse of this software. Users are solely responsible for ensuring their use complies with all applicable laws and regulations.

---

## Contact

**Legal Questions:** legal@cybermindcli.com
**Abuse Reports:** abuse@cybermindcli.com
**Security Issues:** security@cybermindcli.com

---

## License

**Proprietary — All rights reserved.**

© 2026 Chandan Pandey
