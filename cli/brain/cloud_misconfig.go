// cloud_misconfig.go — Cloud Misconfiguration Scanner
// Detects: S3 public buckets, GCS buckets, Azure blobs, Firebase, subdomain takeover.
package brain

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// CloudFinding represents a cloud misconfiguration finding
type CloudFinding struct {
	Type        string
	Provider    string
	URL         string
	BucketName  string
	Severity    string
	Description string
	Evidence    string
	PoC         string
	Impact      string
}

// CloudScanResult holds all cloud misconfiguration findings
type CloudScanResult struct {
	Target   string
	Findings []CloudFinding
	Duration time.Duration
}

var cloudClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// ScanCloudMisconfigurations performs comprehensive cloud misconfiguration scanning
func ScanCloudMisconfigurations(target string, subdomains []string) CloudScanResult {
	start := time.Now()
	result := CloudScanResult{Target: target}
	companyName := extractCompanyName(target)
	bucketNames := generateBucketNames(companyName)

	var mu sync.Mutex
	var wg sync.WaitGroup

	addFinding := func(f CloudFinding) {
		mu.Lock()
		result.Findings = append(result.Findings, f)
		mu.Unlock()
	}

	// AWS S3
	for _, bucket := range bucketNames {
		b := bucket
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f := checkS3Bucket(b); f != nil {
				addFinding(*f)
			}
		}()
	}

	// GCS
	for _, bucket := range bucketNames {
		b := bucket
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f := checkGCSBucket(b); f != nil {
				addFinding(*f)
			}
		}()
	}

	// Azure
	for _, bucket := range bucketNames {
		b := bucket
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f := checkAzureBlob(b); f != nil {
				addFinding(*f)
			}
		}()
	}

	// Firebase
	for _, bucket := range bucketNames {
		b := bucket
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f := checkFirebase(b); f != nil {
				addFinding(*f)
			}
		}()
	}

	// Subdomain takeover
	for _, sub := range subdomains {
		s := sub
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f := checkSubdomainCloudTakeover(s); f != nil {
				addFinding(*f)
			}
		}()
	}

	// AWS Metadata SSRF
	wg.Add(1)
	go func() {
		defer wg.Done()
		if f := checkAWSMetadataSSRF(target); f != nil {
			addFinding(*f)
		}
	}()

	wg.Wait()
	result.Duration = time.Since(start)
	return result
}

func checkS3Bucket(bucketName string) *CloudFinding {
	urls := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName),
		fmt.Sprintf("https://s3.amazonaws.com/%s/", bucketName),
	}
	for _, u := range urls {
		resp, err := cloudClient.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		bodyStr := string(body)
		if resp.StatusCode == 200 && strings.Contains(bodyStr, "ListBucketResult") {
			return &CloudFinding{
				Type: "s3_public_read", Provider: "aws", URL: u, BucketName: bucketName,
				Severity:    "critical",
				Description: fmt.Sprintf("S3 bucket '%s' is publicly readable", bucketName),
				Evidence:    bodyStr[:min(500, len(bodyStr))],
				PoC:         fmt.Sprintf("aws s3 ls s3://%s --no-sign-request\ncurl %s", bucketName, u),
				Impact:      "All files in bucket are publicly accessible — potential data breach",
			}
		}
	}
	return nil
}

func checkGCSBucket(bucketName string) *CloudFinding {
	u := fmt.Sprintf("https://storage.googleapis.com/%s/", bucketName)
	resp, err := cloudClient.Get(u)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	resp.Body.Close()
	bodyStr := string(body)
	if resp.StatusCode == 200 && (strings.Contains(bodyStr, "ListBucketResult") ||
		strings.Contains(bodyStr, "\"kind\": \"storage#objects\"")) {
		return &CloudFinding{
			Type: "gcs_public_read", Provider: "gcp", URL: u, BucketName: bucketName,
			Severity:    "critical",
			Description: fmt.Sprintf("GCS bucket '%s' is publicly readable", bucketName),
			Evidence:    bodyStr[:min(500, len(bodyStr))],
			PoC:         fmt.Sprintf("gsutil ls gs://%s\ncurl '%s'", bucketName, u),
			Impact:      "All files in GCS bucket are publicly accessible",
		}
	}
	return nil
}

func checkAzureBlob(accountName string) *CloudFinding {
	for _, container := range []string{"backup", "backups", "data", "files", "uploads", "public", "static", "assets", "logs"} {
		u := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", accountName, container)
		resp, err := cloudClient.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		bodyStr := string(body)
		if resp.StatusCode == 200 && strings.Contains(bodyStr, "EnumerationResults") {
			return &CloudFinding{
				Type: "azure_blob_public", Provider: "azure", URL: u,
				BucketName:  accountName + "/" + container,
				Severity:    "critical",
				Description: fmt.Sprintf("Azure Blob container '%s/%s' is publicly accessible", accountName, container),
				Evidence:    bodyStr[:min(500, len(bodyStr))],
				PoC:         fmt.Sprintf("curl '%s'", u),
				Impact:      "Azure Blob container contents are publicly accessible",
			}
		}
	}
	return nil
}

func checkFirebase(projectName string) *CloudFinding {
	for _, u := range []string{
		fmt.Sprintf("https://%s.firebaseio.com/.json", projectName),
		fmt.Sprintf("https://%s-default-rtdb.firebaseio.com/.json", projectName),
	} {
		resp, err := cloudClient.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		bodyStr := string(body)
		if resp.StatusCode == 200 && bodyStr != "null" && len(bodyStr) > 10 {
			return &CloudFinding{
				Type: "firebase_open_database", Provider: "gcp", URL: u, BucketName: projectName,
				Severity:    "critical",
				Description: fmt.Sprintf("Firebase Realtime Database '%s' is publicly readable", projectName),
				Evidence:    bodyStr[:min(500, len(bodyStr))],
				PoC:         fmt.Sprintf("curl '%s'", u),
				Impact:      "All Firebase database contents are publicly accessible",
			}
		}
	}
	return nil
}

func checkAWSMetadataSSRF(target string) *CloudFinding {
	resp, err := cloudClient.Get("http://169.254.169.254/latest/meta-data/")
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == 200 && strings.Contains(string(body), "ami-id") {
		return &CloudFinding{
			Type: "aws_metadata_accessible", Provider: "aws",
			URL: "http://169.254.169.254/latest/meta-data/", BucketName: target,
			Severity:    "critical",
			Description: "AWS EC2 metadata service (IMDSv1) is accessible",
			Evidence:    string(body)[:min(300, len(body))],
			PoC:         "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			Impact:      "AWS IAM credentials accessible — full AWS account compromise possible",
		}
	}
	return nil
}

func checkSubdomainCloudTakeover(subdomain string) *CloudFinding {
	fingerprints := map[string]struct{ provider, severity string }{
		"NoSuchBucket":                         {"aws-s3", "critical"},
		"The specified bucket does not exist":  {"aws-s3", "critical"},
		"Repository not found":                 {"github-pages", "high"},
		"There isn't a GitHub Pages site here": {"github-pages", "high"},
		"Fastly error: unknown domain":         {"fastly", "high"},
		"project not found":                    {"gitlab-pages", "high"},
		"Unrecognized domain":                  {"zendesk", "medium"},
	}
	if !strings.HasPrefix(subdomain, "http") {
		subdomain = "https://" + subdomain
	}
	resp, err := cloudClient.Get(subdomain)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	resp.Body.Close()
	bodyStr := string(body)
	for fingerprint, info := range fingerprints {
		if strings.Contains(bodyStr, fingerprint) {
			return &CloudFinding{
				Type: "subdomain_takeover", Provider: info.provider, URL: subdomain,
				BucketName:  subdomain,
				Severity:    info.severity,
				Description: fmt.Sprintf("Subdomain takeover possible on %s (%s)", subdomain, info.provider),
				Evidence:    fmt.Sprintf("Fingerprint: '%s'", fingerprint),
				PoC:         fmt.Sprintf("Register %s account and claim: %s", info.provider, subdomain),
				Impact:      "Attacker can serve malicious content on " + subdomain,
			}
		}
	}
	return nil
}

// RunCloudEnum runs cloud_enum tool if available
func RunCloudEnum(companyName string, onResult func(string)) {
	if _, err := exec.LookPath("cloud_enum"); err != nil {
		cmd := exec.Command("pip3", "install", "cloud-enum", "--break-system-packages", "-q")
		cmd.Stdin = nil
		cmd.Run()
	}
	if _, err := exec.LookPath("cloud_enum"); err != nil {
		onResult("cloud_enum not available — install: pip3 install cloud-enum")
		return
	}
	cmd := exec.Command("cloud_enum", "-k", companyName, "-l", "/tmp/cybermind_cloud_enum.txt")
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 120)
	if err == nil {
		onResult(out)
	}
}

func extractCompanyName(target string) string {
	target = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	target = strings.TrimPrefix(target, "www.")
	parts := strings.Split(target, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return target
}

func generateBucketNames(company string) []string {
	suffixes := []string{
		"", "-backup", "-backups", "-data", "-files", "-uploads",
		"-public", "-static", "-assets", "-logs", "-db", "-database",
		"-prod", "-dev", "-staging", "-test", "-media", "-images",
		"-docs", "-private", "-internal", "-admin", "-api", "-cdn",
		"-storage", "-archive", "-2024", "-2023",
	}
	var names []string
	for _, suffix := range suffixes {
		names = append(names, company+suffix)
	}
	return names
}

// FormatCloudReport returns a human-readable cloud misconfiguration report
func FormatCloudReport(result CloudScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  ☁️  Cloud Misconfiguration Scan — %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("  Duration: %s | Findings: %d\n\n",
		result.Duration.Round(time.Second), len(result.Findings)))
	if len(result.Findings) == 0 {
		sb.WriteString("  No cloud misconfigurations found.\n")
		return sb.String()
	}
	for i, f := range result.Findings {
		sb.WriteString(fmt.Sprintf("  [%d] [%s] [%s] %s\n", i+1,
			strings.ToUpper(f.Severity), strings.ToUpper(f.Provider), f.Type))
		sb.WriteString(fmt.Sprintf("      URL: %s\n", f.URL))
		sb.WriteString(fmt.Sprintf("      %s\n", f.Description))
		sb.WriteString(fmt.Sprintf("      Impact: %s\n", f.Impact))
		if f.PoC != "" {
			sb.WriteString(fmt.Sprintf("      PoC: %s\n", f.PoC))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
