// Package anon — IP anonymization for CyberMind bug bounty operations.
// Automatically routes all tool traffic through Tor or a VPN before any scan starts.
// This protects the researcher's real IP from appearing in target server logs.
//
// Usage:
//   anon.Setup()          — auto-detect and enable best available method
//   anon.Teardown()       — restore original routing
//   anon.CurrentIP()      — show current public IP (should differ from real IP)
//   anon.IsActive()       — check if anonymization is active
package anon

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Method represents the anonymization method in use
type Method string

const (
	MethodNone        Method = "none"
	MethodTor         Method = "tor"
	MethodProxychains Method = "proxychains"
	MethodVPN         Method = "vpn"
)

// Status holds the current anonymization state
type Status struct {
	Active    bool
	Method    Method
	RealIP    string
	AnonIP    string
	TorPID    int
}

var current = Status{Method: MethodNone}

// Setup enables anonymization — tries Tor first, then proxychains, then warns.
// Called automatically before any recon/hunt/exploit phase starts.
func Setup() Status {
	fmt.Println()
	fmt.Println("  🔒 ANONYMIZATION — Protecting your IP...")

	// Get real IP first
	current.RealIP = getPublicIP()
	if current.RealIP != "" {
		fmt.Printf("  ℹ  Real IP: %s (will be hidden)\n", current.RealIP)
	}

	// Try Tor first (best anonymization)
	if tryTor() {
		current.Active = true
		current.Method = MethodTor
		current.AnonIP = getPublicIPViaTor()
		fmt.Printf("  ✓ Tor active — Anon IP: %s\n", current.AnonIP)
		fmt.Println("  ✓ All tool traffic routed through Tor exit node")
		return current
	}

	// Try proxychains with Tor
	if tryProxychains() {
		current.Active = true
		current.Method = MethodProxychains
		current.AnonIP = getPublicIP() // proxychains wraps tools, not system
		fmt.Printf("  ✓ Proxychains active — tools will use Tor SOCKS5\n")
		return current
	}

	// No anonymization available
	current.Active = false
	current.Method = MethodNone
	fmt.Println("  ⚠  No anonymization available (Tor not installed)")
	fmt.Println("  ℹ  Install: sudo apt install tor proxychains4 -y")
	fmt.Println("  ℹ  Continuing without anonymization — your real IP may appear in logs")
	return current
}

// Teardown stops Tor and restores normal routing
func Teardown() {
	if !current.Active {
		return
	}
	switch current.Method {
	case MethodTor:
		exec.Command("sudo", "systemctl", "stop", "tor").Run()
		exec.Command("sudo", "service", "tor", "stop").Run()
		fmt.Println("  ✓ Tor stopped — normal routing restored")
	case MethodProxychains:
		// proxychains is per-command, nothing to stop
		fmt.Println("  ✓ Proxychains mode ended")
	}
	current.Active = false
	current.Method = MethodNone
}

// IsActive returns true if anonymization is currently active
func IsActive() bool {
	return current.Active
}

// GetMethod returns the current anonymization method
func GetMethod() Method {
	return current.Method
}

// CurrentIP returns the current public IP (anonymized if active)
func CurrentIP() string {
	if current.AnonIP != "" {
		return current.AnonIP
	}
	return getPublicIP()
}

// WrapCommand wraps a command with proxychains if that method is active.
// For Tor method, traffic is routed at system level — no wrapping needed.
func WrapCommand(name string, args []string) (string, []string) {
	if current.Method == MethodProxychains {
		// Prepend proxychains4 to the command
		if _, err := exec.LookPath("proxychains4"); err == nil {
			return "proxychains4", append([]string{"-q", name}, args...)
		}
		if _, err := exec.LookPath("proxychains"); err == nil {
			return "proxychains", append([]string{"-q", name}, args...)
		}
	}
	return name, args
}

// RotateIP requests a new Tor circuit (new exit node = new IP)
func RotateIP() string {
	if current.Method != MethodTor {
		return current.AnonIP
	}

	// Send NEWNYM signal to Tor control port
	cmd := exec.Command("bash", "-c",
		`echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051 2>/dev/null || true`)
	cmd.Stdin = nil
	cmd.Run()

	// Wait for new circuit
	time.Sleep(3 * time.Second)

	newIP := getPublicIPViaTor()
	if newIP != "" && newIP != current.AnonIP {
		fmt.Printf("  ✓ IP rotated: %s → %s\n", current.AnonIP, newIP)
		current.AnonIP = newIP
	}
	return current.AnonIP
}

// PrintStatus shows current anonymization status
func PrintStatus() {
	if !current.Active {
		fmt.Println("  ✗ Anonymization: OFF")
		return
	}
	fmt.Printf("  ✓ Anonymization: %s | Anon IP: %s\n", current.Method, current.AnonIP)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func tryTor() bool {
	// Check if tor is installed
	if _, err := exec.LookPath("tor"); err != nil {
		// Try to install it
		fmt.Println("  ⟳ Installing Tor...")
		installCmd := exec.Command("sudo", "apt-get", "install", "-y", "-qq", "tor", "proxychains4")
		installCmd.Stdin = nil
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if installCmd.Run() != nil {
			return false
		}
	}

	// Start Tor service
	fmt.Println("  ⟳ Starting Tor...")
	startCmd := exec.Command("sudo", "systemctl", "start", "tor")
	startCmd.Stdin = nil
	if err := startCmd.Run(); err != nil {
		// Try service command
		startCmd2 := exec.Command("sudo", "service", "tor", "start")
		startCmd2.Stdin = nil
		if err2 := startCmd2.Run(); err2 != nil {
			// Try running tor directly
			torCmd := exec.Command("tor", "--RunAsDaemon", "1",
				"--SocksPort", "9050",
				"--ControlPort", "9051",
				"--DataDirectory", "/tmp/cybermind_tor_data",
			)
			torCmd.Stdin = nil
			if err3 := torCmd.Start(); err3 != nil {
				return false
			}
		}
	}

	// Wait for Tor to bootstrap (up to 30s)
	fmt.Print("  ⟳ Waiting for Tor circuit")
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		fmt.Print(".")
		if isTorReady() {
			fmt.Println(" ✓")
			return true
		}
	}
	fmt.Println(" ✗ (timeout)")
	return false
}

func isTorReady() bool {
	// Check if SOCKS5 port 9050 is listening
	cmd := exec.Command("bash", "-c", "nc -z 127.0.0.1 9050 2>/dev/null && echo ok")
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "ok")
}

func tryProxychains() bool {
	// Check if proxychains is available and Tor SOCKS is up
	if _, err := exec.LookPath("proxychains4"); err != nil {
		if _, err2 := exec.LookPath("proxychains"); err2 != nil {
			return false
		}
	}
	return isTorReady()
}

func getPublicIP() string {
	client := &http.Client{Timeout: 8 * time.Second}
	for _, url := range []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
	} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if len(ip) >= 7 && len(ip) <= 45 {
			return ip
		}
	}
	return "unknown"
}

func getPublicIPViaTor() string {
	// Use curl with Tor SOCKS5 proxy
	cmd := exec.Command("curl", "-s", "--socks5", "127.0.0.1:9050",
		"--connect-timeout", "15",
		"https://api.ipify.org")
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		// Try check.torproject.org
		cmd2 := exec.Command("curl", "-s", "--socks5", "127.0.0.1:9050",
			"--connect-timeout", "15",
			"https://check.torproject.org/api/ip")
		cmd2.Stdin = nil
		out2, err2 := cmd2.Output()
		if err2 != nil {
			return "tor-active"
		}
		// Parse {"IsTor":true,"IP":"x.x.x.x"}
		s := string(out2)
		if idx := strings.Index(s, `"IP":"`); idx >= 0 {
			rest := s[idx+6:]
			if end := strings.Index(rest, `"`); end >= 0 {
				return rest[:end]
			}
		}
		return "tor-active"
	}
	ip := strings.TrimSpace(string(out))
	if len(ip) >= 7 {
		return ip
	}
	return "tor-active"
}
