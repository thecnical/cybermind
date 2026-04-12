package vibecoder

import "strings"

// BrainProfile defines a web interface profile with recommendations.
type BrainProfile struct {
	Name                string
	ComponentRecs       []string
	AnimationPatterns   []string
	LayoutBestPractices []string
	AccessibilityReqs   []string
	PerformanceTips     []string
}

// brainProfiles is the built-in set of 12 web interface profiles.
var brainProfiles = map[string]BrainProfile{
	"landing-page": {Name: "landing-page", ComponentRecs: []string{"Hero", "Features", "CTA", "Footer"}, AnimationPatterns: []string{"scroll-reveal", "parallax"}},
	"dashboard":    {Name: "dashboard", ComponentRecs: []string{"Sidebar", "DataTable", "Charts", "KPICards"}, AnimationPatterns: []string{"skeleton-loading"}},
	"admin-panel":  {Name: "admin-panel", ComponentRecs: []string{"CRUD Table", "Forms", "Modals"}, AnimationPatterns: []string{"transitions"}},
	"e-commerce":   {Name: "e-commerce", ComponentRecs: []string{"ProductGrid", "Cart", "Checkout"}, AnimationPatterns: []string{"hover-effects"}},
	"portfolio":    {Name: "portfolio", ComponentRecs: []string{"Hero", "Projects", "Contact"}, AnimationPatterns: []string{"entrance-animations"}},
	"blog-cms":     {Name: "blog-cms", ComponentRecs: []string{"ArticleList", "MDX", "Tags"}, AnimationPatterns: []string{"page-transitions"}},
	"auth-pages":   {Name: "auth-pages", ComponentRecs: []string{"LoginForm", "SignupForm", "OAuth"}, AnimationPatterns: []string{"form-validation"}},
	"mobile-app":   {Name: "mobile-app", ComponentRecs: []string{"BottomNav", "SwipeCards", "PullRefresh"}, AnimationPatterns: []string{"native-feel"}},
	"docs-site":    {Name: "docs-site", ComponentRecs: []string{"Sidebar", "TOC", "CodeBlock"}, AnimationPatterns: []string{"smooth-scroll"}},
	"saas-app":     {Name: "saas-app", ComponentRecs: []string{"Pricing", "Dashboard", "Onboarding"}, AnimationPatterns: []string{"micro-interactions"}},
	"agency-site":  {Name: "agency-site", ComponentRecs: []string{"Hero", "Portfolio", "Team"}, AnimationPatterns: []string{"bold-transitions"}},
	"web-app":      {Name: "web-app", ComponentRecs: []string{"AppShell", "Routing", "State"}, AnimationPatterns: []string{"loading-states"}},
}

// DetectInterfaceType detects the interface type from a user prompt.
func DetectInterfaceType(prompt string) string {
	lower := strings.ToLower(prompt)
	keywords := map[string]string{
		"landing":   "landing-page",
		"dashboard": "dashboard",
		"admin":     "admin-panel",
		"shop":      "e-commerce",
		"store":     "e-commerce",
		"portfolio": "portfolio",
		"blog":      "blog-cms",
		"login":     "auth-pages",
		"auth":      "auth-pages",
		"mobile":    "mobile-app",
		"docs":      "docs-site",
		"saas":      "saas-app",
		"agency":    "agency-site",
	}
	for kw, profileName := range keywords {
		if strings.Contains(lower, kw) {
			return profileName
		}
	}
	return "web-app"
}

// GetBrainProfile returns the profile for the given interface type.
func GetBrainProfile(interfaceType string) (BrainProfile, bool) {
	p, ok := brainProfiles[interfaceType]
	return p, ok
}

// WebDesignPrinciplesPrompt returns the web design principles layer.
func WebDesignPrinciplesPrompt() string {
	return `
Web Design Principles:
- Mobile-first responsive design
- Accessibility: WCAG 2.1 AA compliance
- Performance: Core Web Vitals optimization
- Semantic HTML structure
- Progressive enhancement
- Consistent spacing and typography
`
}
