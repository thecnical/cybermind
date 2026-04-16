// bizlogic_brain.go — Business Logic Intelligence Engine
// Detects business logic flaws that automated tools miss:
// price manipulation, workflow bypass, race conditions, IDOR chains,
// privilege escalation via logic, and application-specific flaws.
package brain

import (
"fmt"
"strings"
)

// BizLogicPattern represents a known business logic attack pattern.
type BizLogicPattern struct {
Name        string
Category    string // "price", "workflow", "idor", "race", "privilege", "coupon"
Description string
TestSteps   []string
Indicators  []string // URL/param patterns that suggest this is testable
Severity    string
Impact      string
}

// GetBizLogicPatterns returns all known business logic attack patterns.
func GetBizLogicPatterns() []BizLogicPattern {
return []BizLogicPattern{
// ── Price Manipulation ────────────────────────────────────────────
{
Name:        "Negative Price Manipulation",
Category:    "price",
Description: "Set item price to negative value to receive credit",
TestSteps: []string{
"Add item to cart",
"Intercept checkout request",
"Change price parameter to -100",
"Submit — check if credit is applied",
},
Indicators: []string{"price=", "amount=", "total=", "cost=", "cart"},
Severity:   "critical",
Impact:     "Attacker receives money/credit instead of paying",
},
{
Name:        "Zero Price Bypass",
Category:    "price",
Description: "Set item price to 0 to get items for free",
TestSteps: []string{
"Add item to cart",
"Intercept checkout request",
"Change price parameter to 0 or 0.00",
"Submit — check if order completes",
},
Indicators: []string{"price=", "amount=", "total=", "checkout"},
Severity:   "critical",
Impact:     "Attacker obtains items/services for free",
},
{
Name:        "Currency Manipulation",
Category:    "price",
Description: "Change currency to lower-value currency to pay less",
TestSteps: []string{
"Add item to cart (e.g., $100 USD)",
"Intercept checkout request",
"Change currency parameter from USD to INR or VND",
"Submit — check if charged in lower currency",
},
Indicators: []string{"currency=", "cur=", "locale="},
Severity:   "high",
Impact:     "Attacker pays fraction of actual price",
},
{
Name:        "Quantity Integer Overflow",
Category:    "price",
Description: "Set quantity to MAX_INT to overflow to negative/zero",
TestSteps: []string{
"Add item to cart",
"Intercept request",
"Set quantity to 2147483647 (MAX_INT) or 9999999999",
"Check if total overflows to negative",
},
Indicators: []string{"qty=", "quantity=", "count="},
Severity:   "high",
Impact:     "Integer overflow causes free or negative-cost purchase",
},

// ── Workflow Bypass ───────────────────────────────────────────────
{
Name:        "Payment Step Skip",
Category:    "workflow",
Description: "Skip payment step by directly accessing order confirmation URL",
TestSteps: []string{
"Start checkout flow",
"Note the order confirmation URL pattern",
"Skip payment step — directly navigate to confirmation",
"Check if order is marked as paid",
},
Indicators: []string{"step=", "stage=", "checkout", "confirm", "order"},
Severity:   "critical",
Impact:     "Attacker completes purchase without payment",
},
{
Name:        "Email Verification Bypass",
Category:    "workflow",
Description: "Access verified-only features without email verification",
TestSteps: []string{
"Register account without verifying email",
"Directly access features requiring verification",
"Try modifying is_verified parameter in requests",
"Check if verification token can be reused",
},
Indicators: []string{"verify", "confirmed", "activated", "email_verified"},
Severity:   "medium",
Impact:     "Attacker accesses features without completing verification",
},
{
Name:        "2FA Bypass via Response Manipulation",
Category:    "workflow",
Description: "Bypass 2FA by manipulating success/failure response",
TestSteps: []string{
"Enter wrong 2FA code",
"Intercept response",
"Change 'success:false' to 'success:true'",
"Check if authenticated",
},
Indicators: []string{"2fa", "otp", "totp", "mfa", "verify"},
Severity:   "critical",
Impact:     "Complete 2FA bypass — account takeover",
},
{
Name:        "Password Reset Token Reuse",
Category:    "workflow",
Description: "Reuse expired/used password reset tokens",
TestSteps: []string{
"Request password reset",
"Use reset token to change password",
"Try using the same token again",
"Check if token is invalidated after use",
},
Indicators: []string{"reset", "forgot", "token=", "code="},
Severity:   "high",
Impact:     "Account takeover if token not properly invalidated",
},

// ── IDOR Chains ───────────────────────────────────────────────────
{
Name:        "Horizontal IDOR — User Data Access",
Category:    "idor",
Description: "Access other users' data by changing user/object ID",
TestSteps: []string{
"Find requests with user_id, account_id, or order_id",
"Change ID to another user's ID (try sequential IDs)",
"Check if other user's data is returned",
"Test with UUIDs: try predictable patterns",
},
Indicators: []string{"user_id=", "account_id=", "order_id=", "profile_id=", "/users/", "/accounts/"},
Severity:   "high",
Impact:     "Unauthorized access to other users' private data",
},
{
Name:        "Vertical IDOR — Privilege Escalation",
Category:    "idor",
Description: "Access admin/privileged resources by changing role/permission ID",
TestSteps: []string{
"Find requests with role, permission, or admin parameters",
"Change role=user to role=admin",
"Try accessing /admin/ endpoints with regular user token",
"Check if admin actions can be performed",
},
Indicators: []string{"role=", "permission=", "admin", "privilege", "access_level="},
Severity:   "critical",
Impact:     "Privilege escalation to admin — full account/system compromise",
},
{
Name:        "IDOR via Mass Assignment",
Category:    "idor",
Description: "Inject privileged fields via mass assignment in API",
TestSteps: []string{
"Find API endpoints that accept JSON body",
"Add extra fields: {\"role\":\"admin\",\"is_admin\":true}",
"Check if extra fields are accepted and applied",
"Try: {\"balance\":1000000,\"credits\":9999}",
},
Indicators: []string{"/api/", "/v1/", "/v2/", "application/json"},
Severity:   "high",
Impact:     "Attacker can set arbitrary fields including admin status",
},

// ── Race Conditions ───────────────────────────────────────────────
{
Name:        "Race Condition on Coupon/Discount",
Category:    "race",
Description: "Apply same coupon multiple times via concurrent requests",
TestSteps: []string{
"Find coupon/discount application endpoint",
"Send 10-50 concurrent requests with same coupon code",
"Check if coupon is applied multiple times",
"Use Burp Turbo Intruder or custom script",
},
Indicators: []string{"coupon=", "promo=", "discount=", "voucher=", "code="},
Severity:   "high",
Impact:     "Attacker applies discount multiple times for free items",
},
{
Name:        "Race Condition on Transfer/Withdrawal",
Category:    "race",
Description: "Transfer more than available balance via concurrent requests",
TestSteps: []string{
"Find transfer/withdrawal endpoint",
"Send 10 concurrent requests to transfer full balance",
"Check if balance goes negative",
"Use threading: 10 threads, same request simultaneously",
},
Indicators: []string{"transfer", "withdraw", "balance", "send_money"},
Severity:   "critical",
Impact:     "Attacker withdraws more than available balance",
},
{
Name:        "Race Condition on Like/Vote",
Category:    "race",
Description: "Like/vote multiple times via concurrent requests",
TestSteps: []string{
"Find like/vote endpoint",
"Send 100 concurrent requests",
"Check if count increases beyond 1",
},
Indicators: []string{"like", "vote", "upvote", "reaction"},
Severity:   "medium",
Impact:     "Manipulation of engagement metrics",
},

// ── Coupon/Referral Abuse ─────────────────────────────────────────
{
Name:        "Self-Referral Bonus",
Category:    "coupon",
Description: "Refer yourself using different email/account for bonus",
TestSteps: []string{
"Find referral program",
"Create second account with different email",
"Use referral link from account A on account B",
"Check if bonus is credited to both accounts",
},
Indicators: []string{"referral", "invite", "refer", "bonus"},
Severity:   "medium",
Impact:     "Unlimited bonus/credit generation",
},
{
Name:        "Promo Code Brute Force",
Category:    "coupon",
Description: "Enumerate valid promo codes via brute force",
TestSteps: []string{
"Find promo code input field",
"Test common patterns: SAVE10, DISCOUNT20, PROMO2024",
"Brute force 4-6 character alphanumeric codes",
"Check for rate limiting",
},
Indicators: []string{"promo", "coupon", "discount_code", "voucher"},
Severity:   "medium",
Impact:     "Unauthorized discounts via enumerated codes",
},
}
}

// AnalyzeBizLogicOpportunities analyzes a target for business logic attack opportunities.
func AnalyzeBizLogicOpportunities(target string, liveURLs []string, techStack []string) []BizLogicPattern {
patterns := GetBizLogicPatterns()
var relevant []BizLogicPattern

urlStr := strings.ToLower(strings.Join(liveURLs, " "))
techStr := strings.ToLower(strings.Join(techStack, " "))

for _, p := range patterns {
score := 0
for _, indicator := range p.Indicators {
if strings.Contains(urlStr, indicator) || strings.Contains(techStr, indicator) {
score++
}
}
if score > 0 {
relevant = append(relevant, p)
}
}

// Always include IDOR patterns — they apply to almost every target
idorIncluded := false
for _, r := range relevant {
if r.Category == "idor" {
idorIncluded = true
break
}
}
if !idorIncluded {
for _, p := range patterns {
if p.Category == "idor" {
relevant = append(relevant, p)
}
}
}

return relevant
}

// FormatBizLogicReport returns a human-readable business logic analysis.
func FormatBizLogicReport(patterns []BizLogicPattern, target string) string {
var sb strings.Builder
sb.WriteString(fmt.Sprintf("\n  💰 Business Logic Analysis — %s\n", target))
sb.WriteString(fmt.Sprintf("  %d attack patterns identified\n\n", len(patterns)))

for i, p := range patterns {
sb.WriteString(fmt.Sprintf("  [%d] [%s] %s\n", i+1, strings.ToUpper(p.Severity), p.Name))
sb.WriteString(fmt.Sprintf("      Category: %s\n", p.Category))
sb.WriteString(fmt.Sprintf("      %s\n", p.Description))
sb.WriteString("      Steps:\n")
for j, step := range p.TestSteps {
sb.WriteString(fmt.Sprintf("        %d. %s\n", j+1, step))
}
sb.WriteString(fmt.Sprintf("      Impact: %s\n\n", p.Impact))
}
return sb.String()
}
