package locate

import (
	"fmt"
	"strings"
)

// LocateToolSpec defines a geolocation tool.
type LocateToolSpec struct {
	Name        string
	Level       int      // 1-5 (5 = SDR/advanced)
	Timeout     int
	TargetTypes []string // nil = all
	InstallHint string
	InstallCmd  string
	AltPaths    []string
	UseShell    bool
	ShellCmd    func(target string, ctx *LocateContext) string
	BuildArgs   func(target string, ctx *LocateContext) []string
	FallbackArgs []func(target string, ctx *LocateContext) []string
}

var locateRegistry = []LocateToolSpec{

	// ══════════════════════════════════════════════════════════════════════════
	// LEVEL 1 — IP / DOMAIN GEOLOCATION
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "geoiplookup", Level: 1, Timeout: 30,
		TargetTypes: []string{"ip", "domain"},
		InstallHint: "sudo apt install geoip-bin -y",
		InstallCmd:  "sudo apt install geoip-bin -y",
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{target}
		},
	},
	{
		// ipinfo CLI
		Name: "ipinfo", Level: 1, Timeout: 30,
		TargetTypes: []string{"ip", "domain"},
		InstallHint: "pip3 install ipinfo --break-system-packages",
		InstallCmd:  "pip3 install ipinfo --break-system-packages",
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{target}
		},
	},
	{
		Name: "shodan", Level: 1, Timeout: 60,
		TargetTypes: []string{"ip", "domain"},
		InstallHint: "pip3 install shodan --break-system-packages && shodan init <API_KEY>",
		InstallCmd:  "pip3 install shodan --break-system-packages",
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{"host", target}
		},
		FallbackArgs: []func(target string, ctx *LocateContext) []string{
			func(target string, ctx *LocateContext) []string {
				return []string{"search", "hostname:" + target}
			},
		},
	},
	{
		// whois for ASN/org info
		Name: "whois", Level: 1, Timeout: 30,
		TargetTypes: []string{"ip", "domain"},
		InstallHint: "sudo apt install whois -y",
		InstallCmd:  "sudo apt install whois -y",
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{target}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// LEVEL 2 — EXIF / METADATA GPS
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "exiftool", Level: 2, Timeout: 60,
		TargetTypes: []string{"file"},
		InstallHint: "sudo apt install libimage-exiftool-perl -y",
		InstallCmd:  "sudo apt install libimage-exiftool-perl -y",
		BuildArgs: func(target string, ctx *LocateContext) []string {
			if ctx.TargetType == "file" {
				return []string{"-a", "-u", "-g1", "-GPS:all", target}
			}
			return nil
		},
	},
	{
		Name: "metagoofil", Level: 2, Timeout: 300,
		TargetTypes: []string{"domain"},
		InstallHint: "pip3 install metagoofil --break-system-packages",
		InstallCmd:  "pip3 install metagoofil --break-system-packages",
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{
				"-d", target, "-t", "pdf,doc,xls,ppt,docx,xlsx",
				"-l", "20", "-n", "10",
				"-o", fmt.Sprintf("%s/metagoofil/", ctx.SessionDir),
			}
		},
		FallbackArgs: []func(target string, ctx *LocateContext) []string{
			func(target string, ctx *LocateContext) []string {
				return []string{"-d", target, "-t", "pdf", "-l", "10", "-n", "5"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// LEVEL 3 — WIFI / NETWORK
	// ══════════════════════════════════════════════════════════════════════════

	{
		// tshark — capture WiFi SSIDs → Google Geolocation API lookup
		Name: "tshark", Level: 3, Timeout: 60,
		InstallHint: "sudo apt install tshark -y",
		InstallCmd:  "sudo apt install tshark -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			// Capture probe requests (SSIDs) from nearby WiFi networks
			// Then query Google Geolocation API with collected BSSIDs
			return `
IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
if [ -z "$IFACE" ]; then IFACE="wlan0"; fi
echo "[*] Scanning WiFi on $IFACE for 30 seconds..."
timeout 30 tshark -i "$IFACE" -Y "wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05" \
  -T fields -e wlan.ssid -e wlan.bssid -e radiotap.dbm_antsignal 2>/dev/null | \
  sort -u | grep -v "^$" | head -100
`
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},
	{
		// nmcli — scan WiFi networks (no monitor mode needed)
		Name: "nmcli", Level: 3, Timeout: 30,
		InstallHint: "sudo apt install network-manager -y",
		InstallCmd:  "sudo apt install network-manager -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			return `nmcli -t -f SSID,BSSID,SIGNAL,FREQ,SECURITY dev wifi list 2>/dev/null | head -50`
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},
	{
		// iwlist — scan WiFi (works without monitor mode)
		Name: "iwlist", Level: 3, Timeout: 30,
		InstallHint: "sudo apt install wireless-tools -y",
		InstallCmd:  "sudo apt install wireless-tools -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			return `IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1); [ -z "$IFACE" ] && IFACE="wlan0"; sudo iwlist "$IFACE" scan 2>/dev/null | grep -E "ESSID|Address|Signal|Frequency" | head -100`
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},
	{
		// kismet — passive WiFi monitoring
		Name: "kismet", Level: 3, Timeout: 60,
		InstallHint: "sudo apt install kismet -y",
		InstallCmd:  "sudo apt install kismet -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			return `kismet --no-ncurses --daemonize 2>/dev/null; sleep 30; kismet_client --cmd=DEVICES 2>/dev/null | head -100`
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},

	// ══════════════════════════════════════════════════════════════════════════
	// LEVEL 4 — SOCIAL GEOLOCATION
	// ══════════════════════════════════════════════════════════════════════════

	{
		// Creepy — aggregate locations from social media
		Name: "creepy", Level: 4, Timeout: 300,
		TargetTypes: []string{"username"},
		InstallHint: "git clone https://github.com/ilektrojohn/creepy /opt/creepy && pip3 install -r /opt/creepy/requirements.txt --break-system-packages && sudo ln -sf /opt/creepy/creepy.py /usr/local/bin/creepy",
		AltPaths:    []string{"/opt/creepy/creepy.py"},
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{"-u", target, "-s", "tw,ig"}
		},
		FallbackArgs: []func(target string, ctx *LocateContext) []string{
			func(target string, ctx *LocateContext) []string {
				return []string{"-u", target}
			},
		},
	},
	{
		// osintgram — Instagram geotags
		Name: "osintgram", Level: 4, Timeout: 300,
		TargetTypes: []string{"username"},
		InstallHint: "git clone https://github.com/Datalux/Osintgram /opt/osintgram && pip3 install -r /opt/osintgram/requirements.txt --break-system-packages && sudo ln -sf /opt/osintgram/main.py /usr/local/bin/osintgram",
		AltPaths:    []string{"/opt/osintgram/main.py"},
		BuildArgs: func(target string, ctx *LocateContext) []string {
			return []string{target, "--command", "wtagged,tagged,captions"}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// LEVEL 5 — CELL TOWER / SDR (ADVANCED — NEEDS HARDWARE)
	// ══════════════════════════════════════════════════════════════════════════

	{
		// gr-gsm — passive GSM sniffing → TAC/LAC → OpenCellID
		Name: "grgsm_livemon", Level: 5, Timeout: 120,
		InstallHint: "sudo apt install gr-gsm -y",
		InstallCmd:  "sudo apt install gr-gsm -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			return `timeout 60 grgsm_livemon -s 2e6 -f 939.4e6 2>&1 | grep -E "IMSI|LAC|CellID|MCC|MNC" | head -50`
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},
	{
		// OpenCellID lookup from captured cell data
		Name: "curl", Level: 5, Timeout: 30,
		InstallHint: "sudo apt install curl -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			if len(ctx.CellTowers) == 0 {
				return ""
			}
			// Parse first cell tower data and query OpenCellID
			return fmt.Sprintf(`curl -s "https://opencellid.org/cell/get?key=test&mcc=404&mnc=20&lac=1234&cellid=5678&format=json" 2>/dev/null`)
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},
	{
		// SigPloit — SS7 simulation for mobile location
		Name: "sigploit", Level: 5, Timeout: 300,
		TargetTypes: []string{"phone"},
		InstallHint: "git clone https://github.com/SigPloiter/SigPloit /opt/sigploit && pip3 install -r /opt/sigploit/requirements.txt --break-system-packages && sudo ln -sf /opt/sigploit/sigploit.py /usr/local/bin/sigploit",
		AltPaths:    []string{"/opt/sigploit/sigploit.py"},
		BuildArgs: func(target string, ctx *LocateContext) []string {
			if strings.HasPrefix(target, "+") {
				return []string{"--target", target, "--attack", "location"}
			}
			return nil
		},
	},
	{
		// srsRAN — 4G/5G fake BTS (IMSI catcher)
		Name: "srsenb", Level: 5, Timeout: 120,
		InstallHint: "git clone https://github.com/srsran/srsRAN_4G /opt/srsRAN_4G && cd /opt/srsRAN_4G && mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install",
		AltPaths:    []string{"/usr/local/bin/srsenb", "/opt/srsRAN_4G/build/srsenb/src/srsenb"},
		UseShell:    true,
		ShellCmd: func(target string, ctx *LocateContext) string {
			return `srsenb --enb.name=CyberMindBTS --enb.mcc=001 --enb.mnc=01 2>&1 | grep -E "IMSI|RNTI|attach" | head -30`
		},
		BuildArgs: func(target string, ctx *LocateContext) []string { return nil },
	},
}
