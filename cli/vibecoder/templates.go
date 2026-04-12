package vibecoder

// Template represents a project template.
type Template struct {
	Name         string
	Description  string
	TechStack    []string
	ASCIIPreview string
}

// BuiltinTemplates is the list of available project templates.
var BuiltinTemplates = []Template{
	{Name: "saas-landing", Description: "SaaS Landing Page", TechStack: []string{"Next.js", "Tailwind", "shadcn/ui"}},
	{Name: "portfolio", Description: "Portfolio Site", TechStack: []string{"Next.js", "Framer Motion"}},
	{Name: "agency", Description: "Agency Website", TechStack: []string{"Next.js", "GSAP", "Tailwind"}},
	{Name: "e-commerce", Description: "E-commerce Store", TechStack: []string{"Next.js", "Stripe", "Tailwind"}},
	{Name: "blog", Description: "Blog/CMS", TechStack: []string{"Next.js", "MDX", "Tailwind"}},
	{Name: "dashboard", Description: "Admin Dashboard", TechStack: []string{"React", "Recharts", "shadcn/ui"}},
	{Name: "docs-site", Description: "Documentation Site", TechStack: []string{"Next.js", "MDX"}},
	{Name: "social-app", Description: "Social Application", TechStack: []string{"Next.js", "Supabase"}},
	{Name: "animated-hero", Description: "Animated Hero Section", TechStack: []string{"React", "GSAP"}},
	{Name: "pricing-table", Description: "Pricing Table", TechStack: []string{"React", "Tailwind"}},
}

// FindTemplate returns a template by name.
func FindTemplate(name string) (Template, bool) {
	for _, t := range BuiltinTemplates {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}
