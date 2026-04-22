package reveng

import (
	"fmt"
	"os"
)

// RevEngToolSpec defines a reverse engineering tool.
type RevEngToolSpec struct {
	Name        string
	Phase       int
	Timeout     int
	TargetTypes []string // nil = all; filter by file type
	Modes       []string // nil = all; filter by analysis mode
	InstallHint string
	InstallCmd  string
	AltPaths    []string
	UseShell    bool
	ShellCmd    func(target string, ctx *RevEngContext) string
	BuildArgs   func(target string, ctx *RevEngContext) []string
	FallbackArgs []func(target string, ctx *RevEngContext) []string
}

// revEngRegistry — full RE arsenal, 6 phases.
var revEngRegistry = []RevEngToolSpec{

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 1 — FILE IDENTIFICATION + METADATA
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "file", Phase: 1, Timeout: 30,
		InstallHint: "sudo apt install file -y",
		InstallCmd:  "sudo apt install file -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-b", "--mime", target}
		},
	},
	{
		Name: "sha256sum", Phase: 1, Timeout: 30,
		InstallHint: "sudo apt install coreutils -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{target}
		},
	},
	{
		Name: "strings", Phase: 1, Timeout: 60,
		InstallHint: "sudo apt install binutils -y",
		InstallCmd:  "sudo apt install binutils -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-a", "-n", "6", "-t", "x", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-n", "4", target}
			},
		},
	},
	{
		Name: "readelf", Phase: 1, Timeout: 60,
		TargetTypes: []string{"elf"},
		InstallHint: "sudo apt install binutils -y",
		InstallCmd:  "sudo apt install binutils -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-a", "-W", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-h", "-S", "-d", target}
			},
		},
	},
	{
		Name: "objdump", Phase: 1, Timeout: 120,
		TargetTypes: []string{"elf", "pe", "macho"},
		InstallHint: "sudo apt install binutils -y",
		InstallCmd:  "sudo apt install binutils -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-d", "-t", "-R", "-x", "--no-show-raw-insn", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-d", "-t", target}
			},
		},
	},
	{
		Name: "exiftool", Phase: 1, Timeout: 60,
		InstallHint: "sudo apt install libimage-exiftool-perl -y",
		InstallCmd:  "sudo apt install libimage-exiftool-perl -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-a", "-u", "-g1", target}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2 — STATIC ANALYSIS
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "checksec", Phase: 2, Timeout: 30,
		TargetTypes: []string{"elf", "pe"},
		InstallHint: "pip3 install checksec.py --break-system-packages",
		InstallCmd:  "pip3 install checksec.py --break-system-packages",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"--file", target, "--output", "json"}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"--file", target}
			},
		},
	},
	{
		// radare2 — deep analysis, function listing, disassembly
		Name: "r2", Phase: 2, Timeout: 300,
		TargetTypes: []string{"elf", "pe", "macho"},
		InstallHint: "sudo apt install radare2 -y",
		InstallCmd:  "sudo apt install radare2 -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{
				"-A", "-q",
				"-c", "aaa;afl;iz;ii;ie;iS;pdf @ main;q",
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-A", "-q", "-c", "aaa;afl;iz;ii;q", target}
			},
		},
	},
	{
		// rizin — r2 fork with better scripting
		Name: "rizin", Phase: 2, Timeout: 300,
		TargetTypes: []string{"elf", "pe", "macho"},
		InstallHint: "sudo apt install rizin -y",
		InstallCmd:  "sudo apt install rizin -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-qc", "aaa;afl~main;pdf @ sym.main;q", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-qc", "aaa;afl;q", target}
			},
		},
	},
	{
		Name: "binwalk", Phase: 2, Timeout: 600,
		InstallHint: "sudo apt install binwalk -y",
		InstallCmd:  "sudo apt install binwalk -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			outDir := fmt.Sprintf("%s/binwalk_extract", ctx.SessionDir)
			return []string{"-e", "-M", "-C", outDir, "--dd", ".*", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-B", target}
			},
		},
	},
	{
		Name: "nm", Phase: 2, Timeout: 60,
		TargetTypes: []string{"elf", "macho"},
		InstallHint: "sudo apt install binutils -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-D", "-C", "--defined-only", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-D", target}
			},
		},
	},
	{
		Name: "ldd", Phase: 2, Timeout: 30,
		TargetTypes: []string{"elf"},
		InstallHint: "sudo apt install libc-bin -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-v", target}
		},
	},
	{
		// floss — FLARE Obfuscated String Solver
		Name: "floss", Phase: 2, Timeout: 300,
		InstallHint: "pip3 install floss --break-system-packages",
		InstallCmd:  "pip3 install floss --break-system-packages",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{
				"--no-progress",
				"-j", fmt.Sprintf("%s/floss.json", ctx.SessionDir),
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"--no-progress", target}
			},
		},
	},
	{
		// die — detect-it-easy: packer/protector/compiler detection
		Name: "diec", Phase: 2, Timeout: 60,
		InstallHint: "sudo apt install detect-it-easy -y",
		InstallCmd:  "sudo apt install detect-it-easy -y",
		AltPaths:    []string{"/usr/bin/diec", "/usr/local/bin/die"},
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-j", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{target}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 3 — DYNAMIC ANALYSIS
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "strace", Phase: 3, Timeout: 60,
		TargetTypes: []string{"elf"},
		Modes:       []string{"dynamic", "all"},
		InstallHint: "sudo apt install strace -y",
		InstallCmd:  "sudo apt install strace -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{
				"-f", "-e", "trace=all",
				"-o", fmt.Sprintf("%s/strace.txt", ctx.SessionDir),
				"-s", "256", target,
			}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-f", "-o", fmt.Sprintf("%s/strace.txt", ctx.SessionDir), target}
			},
		},
	},
	{
		Name: "ltrace", Phase: 3, Timeout: 60,
		TargetTypes: []string{"elf"},
		Modes:       []string{"dynamic", "all"},
		InstallHint: "sudo apt install ltrace -y",
		InstallCmd:  "sudo apt install ltrace -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-x", "*", "-e", "malloc,free,strcpy,strcmp,system,execve", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{target}
			},
		},
	},
	{
		// gdb with pwndbg — automated batch analysis
		Name: "gdb", Phase: 3, Timeout: 60,
		TargetTypes: []string{"elf"},
		Modes:       []string{"dynamic", "all"},
		InstallHint: "sudo apt install gdb -y",
		InstallCmd:  "sudo apt install gdb -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *RevEngContext) string {
			scriptFile := fmt.Sprintf("%s/gdb_script.gdb", ctx.SessionDir)
			script := fmt.Sprintf("set pagination off\nset disassembly-flavor intel\nfile %s\ninfo functions\ninfo variables\ndisassemble main\nquit\n", target)
			os.WriteFile(scriptFile, []byte(script), 0600)
			return fmt.Sprintf("gdb -batch -x %s %s 2>/dev/null", scriptFile, target)
		},
		BuildArgs: func(target string, ctx *RevEngContext) []string { return nil },
	},
	{
		// frida-trace — dynamic instrumentation
		Name: "frida-trace", Phase: 3, Timeout: 120,
		TargetTypes: []string{"elf", "apk"},
		Modes:       []string{"dynamic", "all"},
		InstallHint: "pip3 install frida-tools --break-system-packages",
		InstallCmd:  "pip3 install frida-tools --break-system-packages",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-f", target, "-i", "malloc", "-i", "free", "-i", "strcmp", "--no-pause"}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"--version"}
			},
		},
	},
	{
		// QEMU user mode — emulate foreign arch binaries
		Name: "qemu-x86_64", Phase: 3, Timeout: 60,
		TargetTypes: []string{"elf"},
		Modes:       []string{"dynamic", "all"},
		InstallHint: "sudo apt install qemu-user-static -y",
		InstallCmd:  "sudo apt install qemu-user-static -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			if ctx.Architecture == "x86_64" || ctx.Architecture == "" {
				return []string{"-strace", target}
			}
			return nil
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 4 — VULNERABILITY DISCOVERY
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "ROPgadget", Phase: 4, Timeout: 300,
		TargetTypes: []string{"elf", "pe", "macho"},
		InstallHint: "pip3 install ROPgadget --break-system-packages",
		InstallCmd:  "pip3 install ROPgadget --break-system-packages",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{
				"--binary", target,
				"--rop", "--jop", "--ret", "--depth", "10", "--multibr",
				"--output", fmt.Sprintf("%s/ropgadgets.txt", ctx.SessionDir),
			}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"--binary", target, "--rop"}
			},
		},
	},
	{
		// pwntools checksec
		Name: "pwn", Phase: 4, Timeout: 30,
		TargetTypes: []string{"elf"},
		InstallHint: "pip3 install pwntools --break-system-packages",
		InstallCmd:  "pip3 install pwntools --break-system-packages",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"checksec", "--file", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"--version"}
			},
		},
	},
	{
		// angr — symbolic execution for automated vuln discovery
		Name: "angr", Phase: 4, Timeout: 600,
		TargetTypes: []string{"elf"},
		InstallHint: "pip3 install angr --break-system-packages",
		InstallCmd:  "pip3 install angr --break-system-packages",
		UseShell:    true,
		ShellCmd: func(target string, ctx *RevEngContext) string {
			return fmt.Sprintf(`python3 -c "
import angr, sys
try:
    proj = angr.Project('%s', auto_load_libs=False)
    print('Entry:', hex(proj.entry))
    print('Arch:', proj.arch.name)
    print('OS:', proj.loader.main_object.os)
    cfg = proj.analyses.CFGFast()
    print('Functions:', len(cfg.kb.functions))
    for addr, func in list(cfg.kb.functions.items())[:20]:
        print(f'  0x{addr:x}: {func.name}')
except Exception as e:
    print('angr error:', e); sys.exit(1)
" 2>/dev/null`, target)
		},
		BuildArgs: func(target string, ctx *RevEngContext) []string { return nil },
	},
	{
		// cve-bin-tool — scan binary for known CVEs
		Name: "cve-bin-tool", Phase: 4, Timeout: 300,
		InstallHint: "pip3 install cve-bin-tool --break-system-packages",
		InstallCmd:  "pip3 install cve-bin-tool --break-system-packages",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{
				"-f", "json",
				"-o", fmt.Sprintf("%s/cve_report.json", ctx.SessionDir),
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{target}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 5 — MALWARE ANALYSIS
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "yara", Phase: 5, Timeout: 120,
		Modes:       []string{"malware", "all"},
		InstallHint: "sudo apt install yara -y",
		InstallCmd:  "sudo apt install yara -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *RevEngContext) string {
			// Create minimal YARA rules if no system rules exist
			rulesFile := fmt.Sprintf("%s/minimal.yar", ctx.SessionDir)
			rules := `rule SuspiciousStrings {
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "/bin/sh" nocase
        $d = "wget http" nocase
        $e = "curl http" nocase
        $f = "base64" nocase
        $g = "eval(" nocase
        $h = "/etc/passwd" nocase
        $i = "nc -e" nocase
    condition: any of them
}`
			os.WriteFile(rulesFile, []byte(rules), 0600)
			// Try system rules first, fallback to minimal
			return fmt.Sprintf(`yara -r /usr/share/yara-rules %s 2>/dev/null || yara %s %s 2>/dev/null`, target, rulesFile, target)
		},
		BuildArgs: func(target string, ctx *RevEngContext) []string { return nil },
	},
	{
		Name: "ssdeep", Phase: 5, Timeout: 60,
		Modes:       []string{"malware", "all"},
		InstallHint: "sudo apt install ssdeep -y",
		InstallCmd:  "sudo apt install ssdeep -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-b", target}
		},
	},
	{
		Name: "clamscan", Phase: 5, Timeout: 120,
		Modes:       []string{"malware", "all"},
		InstallHint: "sudo apt install clamav -y && sudo freshclam",
		InstallCmd:  "sudo apt install clamav -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"--infected", "--remove=no", "--bell", target}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 6 — DECOMPILATION + AI ANALYSIS
	// ══════════════════════════════════════════════════════════════════════════

	{
		// Ghidra headless — NSA's decompiler, best-in-class
		Name: "ghidra_server", Phase: 6, Timeout: 1800,
		TargetTypes: []string{"elf", "pe", "macho"},
		Modes:       []string{"decompile", "all"},
		InstallHint: "Download from https://ghidra-sre.org/ and extract to /opt/ghidra",
		AltPaths:    []string{"/opt/ghidra/support/analyzeHeadless"},
		UseShell:    true,
		ShellCmd: func(target string, ctx *RevEngContext) string {
			ghidraPath := "/opt/ghidra/support/analyzeHeadless"
			if _, err := os.Stat(ghidraPath); err != nil {
				return "echo 'Ghidra not found at /opt/ghidra — install from https://ghidra-sre.org/'"
			}
			projectDir := ctx.SessionDir + "/ghidra_project"
			os.MkdirAll(projectDir, 0700)
			return fmt.Sprintf(`%s %s CyberMindRE -import %s -postScript DecompileAllFunctions.java -deleteProject 2>&1 | head -300`,
				ghidraPath, projectDir, target)
		},
		BuildArgs: func(target string, ctx *RevEngContext) []string { return nil },
	},
	{
		// retdec — Avast's C decompiler
		Name: "retdec-decompiler", Phase: 6, Timeout: 600,
		TargetTypes: []string{"elf", "pe"},
		Modes:       []string{"decompile", "all"},
		InstallHint: "sudo apt install retdec -y",
		InstallCmd:  "sudo apt install retdec -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			outFile := fmt.Sprintf("%s/decompiled.c", ctx.DecompileDir)
			return []string{"--output", outFile, "--backend-emit-cfg", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"--output", fmt.Sprintf("%s/decompiled.c", ctx.DecompileDir), target}
			},
		},
	},
	{
		// jadx — Android APK decompiler
		Name: "jadx", Phase: 6, Timeout: 600,
		TargetTypes: []string{"apk", "jar"},
		Modes:       []string{"mobile", "decompile", "all"},
		InstallHint: "sudo apt install jadx -y",
		InstallCmd:  "sudo apt install jadx -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			outDir := fmt.Sprintf("%s/jadx_output", ctx.DecompileDir)
			return []string{"-d", outDir, "--show-bad-code", "--no-res", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-d", fmt.Sprintf("%s/jadx_output", ctx.DecompileDir), target}
			},
		},
	},
	{
		// apktool — APK disassembly to smali
		Name: "apktool", Phase: 6, Timeout: 300,
		TargetTypes: []string{"apk"},
		Modes:       []string{"mobile", "all"},
		InstallHint: "sudo apt install apktool -y",
		InstallCmd:  "sudo apt install apktool -y",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			outDir := fmt.Sprintf("%s/apktool_output", ctx.DecompileDir)
			return []string{"d", "-f", "-o", outDir, target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"d", target}
			},
		},
	},
	{
		// r2ghidra — Ghidra decompiler plugin inside radare2
		Name: "r2", Phase: 6, Timeout: 600,
		TargetTypes: []string{"elf", "pe", "macho"},
		Modes:       []string{"decompile", "all"},
		InstallHint: "sudo apt install radare2 -y && r2pm -ci r2ghidra",
		BuildArgs: func(target string, ctx *RevEngContext) []string {
			return []string{"-A", "-q", "-c", "aaa;s main;pdg;q", target}
		},
		FallbackArgs: []func(target string, ctx *RevEngContext) []string{
			func(target string, ctx *RevEngContext) []string {
				return []string{"-A", "-q", "-c", "aaa;pdf @ main;q", target}
			},
		},
	},
}
