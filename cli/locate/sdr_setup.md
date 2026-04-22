# SDR Hardware Setup Guide — CyberMind /locate-advanced

## What You Need

### Option A — Budget Setup (~$50)
| Hardware | Price | Use |
|----------|-------|-----|
| RTL-SDR Blog V3 | $30 | Passive GSM sniffing (gr-gsm) |
| Telescopic Antenna | $10 | GSM 900/1800 MHz |
| USB Extension Cable | $5 | Better positioning |

**Buy from:** rtl-sdr.com, Amazon, AliExpress

### Option B — Professional Setup (~$500)
| Hardware | Price | Use |
|----------|-------|-----|
| HackRF One | $300 | Full TX/RX, 1MHz-6GHz |
| BladeRF 2.0 xA4 | $420 | High-performance SDR |
| LimeSDR Mini | $159 | Full duplex, 10MHz-3.5GHz |
| Yagi Antenna | $50 | Directional, long range |

**Buy from:** greatscottgadgets.com, nuand.com, limemicro.com

---

## Software Installation

```bash
# 1. Install RTL-SDR drivers
sudo apt install rtl-sdr librtlsdr-dev -y
rtl_test  # verify device detected

# 2. Install gr-gsm (passive GSM sniffing)
sudo apt install gr-gsm -y
grgsm_livemon  # start monitoring

# 3. Install srsRAN (4G/5G fake BTS)
sudo apt install cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev -y
git clone https://github.com/srsran/srsRAN_4G /opt/srsRAN_4G
cd /opt/srsRAN_4G && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install

# 4. Install YateBTS (GSM fake tower)
sudo apt install yatebts -y

# 5. Install OpenBTS-UMTS (3G)
git clone https://github.com/RangeNetworks/openbts-umts /opt/openbts
cd /opt/openbts && ./build.sh

# 6. Install SigPloit (SS7 simulation)
git clone https://github.com/SigPloiter/SigPloit /opt/sigploit
pip3 install -r /opt/sigploit/requirements.txt --break-system-packages
sudo ln -sf /opt/sigploit/sigploit.py /usr/local/bin/sigploit
```

---

## Hardware Connection

```
1. Plug RTL-SDR/HackRF into USB 3.0 port
2. Attach GSM antenna to SMA connector
3. Run: rtl_test -t  (verify device)
4. Run: grgsm_livemon -s 2e6 -f 939.4e6  (start sniffing GSM 900MHz)
5. Extract IMSI/LAC/CellID from output
6. Query OpenCellID API for GPS coordinates
```

---

## Usage with CyberMind

```bash
# Basic geolocation (no hardware needed)
cybermind /locate 8.8.8.8
cybermind /locate target.com
cybermind /locate image.jpg  # EXIF GPS extraction

# Advanced (SDR hardware required)
cybermind /locate-advanced +91XXXXXXXXXX  # phone location via SS7
cybermind /locate-advanced target.com     # cell tower triangulation
```

---

## Legal Warning

**SDR cell tower simulation (srsRAN, YateBTS) is ILLEGAL without authorization.**
- Use ONLY in controlled lab environments
- Use ONLY with explicit written permission
- Unauthorized IMSI catching is a criminal offense in most countries
- CyberMind is not responsible for misuse

---

## Chain Command (gr-gsm → OpenCellID)

```bash
# Capture GSM data and auto-lookup location
grgsm_livemon -s 2e6 -f 939.4e6 2>&1 | \
  grep -oP 'LAC:\K[0-9]+|CellID:\K[0-9]+' | \
  while read lac; read cellid; do
    curl -s "https://opencellid.org/cell/get?key=test&mcc=404&mnc=20&lac=$lac&cellid=$cellid&format=json"
  done
```
