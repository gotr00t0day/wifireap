/*

Wireless Information

Author: c0d3Ninja
Website: https://gotr00t0day.github.io
Instagram: @gotr00t0day

Description:
Enumerates wireless network information from the local Linux system, including
the active interface, connected SSID, BSSID, signal strength, channel, and
frequency. Also reads saved/known network profiles from NetworkManager
(/etc/NetworkManager/system-connections/) and wpa_supplicant configs, which
may expose stored pre-shared keys (PSKs) or credentials in plaintext.
Detects nearby APs running WEP/TKIP (deprecated encryption) or WPS.

*/

#include "../modules/executils.h"
#include <string>
#include <vector>
#include <sstream>

std::vector<std::string> wifiCommands = {"ip link", "iwconfig", "nmcli device status"};

// Returns the first wireless interface name found via `iw dev`
static std::string detectWifiInterface() {
    std::string output = execCommand("iw dev 2>/dev/null");
    std::istringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        auto pos = line.find("Interface ");
        if (pos != std::string::npos) {
            std::string iface = line.substr(pos + 10);
            iface.erase(iface.find_last_not_of(" \t\r\n") + 1);
            return iface;
        }
    }
    return "wlan0";
}

std::vector<std::string> wifiScan() {
    std::vector<std::string> cmdResults;
    for (const auto& wifiCMDS : wifiCommands) {
        if (wifiCMDS == "iwconfig") {
            if (commandExists("iwconfig")) {
                cmdResults.emplace_back(execCommand("iwconfig"));
            } else {
                cmdResults.emplace_back(execCommand("iw dev"));
            }
            continue;
        }
        cmdResults.emplace_back(execCommand(wifiCMDS));
    }
    return cmdResults;
}

// Reads saved WiFi profiles — may expose PSKs in plaintext
static std::vector<std::string> savedNetworkCreds() {
    std::vector<std::string> results;

    std::string nmProfiles = execCommand(
        "grep -rh 'psk\\|password' /etc/NetworkManager/system-connections/ 2>/dev/null"
    );
    if (!nmProfiles.empty() && nmProfiles != "ERROR")
        results.emplace_back("[NetworkManager PSKs]\n" + nmProfiles);

    std::string wpaCfg = execCommand(
        "cat /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null"
    );
    if (!wpaCfg.empty() && wpaCfg != "ERROR")
        results.emplace_back("[wpa_supplicant.conf]\n" + wpaCfg);

    return results;
}

struct APInfo {
    std::string bssid;
    std::string ssid;
    bool wps  = false;
    bool wep  = false;
    bool tkip = false;
};

static std::vector<APInfo> parseAPFlags(const std::string& scanOutput) {
    std::vector<APInfo> aps;
    APInfo current;
    bool hasRSN = false;
    bool hasWPA = false;
    bool hasPrivacy = false;

    std::istringstream ss(scanOutput);
    std::string line;

    auto contains = [](const std::string& s, const std::string& sub) {
        return s.find(sub) != std::string::npos;
    };

    auto flush = [&]() {
        if (current.bssid.empty()) return;
        if (hasPrivacy && !hasRSN && !hasWPA)
            current.wep = true;
        aps.push_back(current);
        current  = APInfo{};
        hasRSN   = false;
        hasWPA   = false;
        hasPrivacy = false;
    };

    while (std::getline(ss, line)) {
        if (contains(line, "BSS ") && line.find(':') != std::string::npos) {
            flush();
            current.bssid = line.substr(4, 17);
        } else if (contains(line, "SSID:")) {
            current.ssid = line.substr(line.find("SSID:") + 6);
            current.ssid.erase(current.ssid.find_last_not_of(" \t\r\n") + 1);
        } else if (contains(line, "WPS:")) {
            current.wps = true;
        } else if (contains(line, "RSN:")) {
            hasRSN = true;
        } else if (contains(line, "WPA:")) {
            hasWPA = true;
        } else if (contains(line, "capability:") && contains(line, "Privacy")) {
            hasPrivacy = true;
        } else if (contains(line, "Group cipher: TKIP") ||
                   contains(line, "Pairwise ciphers: TKIP")) {
            current.tkip = true;
        }
    }
    flush();
    return aps;
}

static std::vector<std::string> scanWeakAPs(const std::string& iface) {
    std::string raw = execCommand("iw dev " + iface + " scan 2>/dev/null");
    if (raw.empty() || raw == "ERROR") {
        // Fall back to nmcli if iw scan fails (e.g. NetworkManager is managing the iface)
        raw = execCommand("nmcli -t -f BSSID,SSID,SECURITY dev wifi list 2>/dev/null");
        std::vector<std::string> findings;
        std::istringstream ss(raw);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("WEP") != std::string::npos)
                findings.push_back("[WEP]  " + line);
            else if (line.find("WPA1") != std::string::npos)
                findings.push_back("[TKIP/WPA1] " + line);
        }
        return findings;
    }

    std::vector<APInfo> aps = parseAPFlags(raw);
    std::vector<std::string> findings;
    for (const auto& ap : aps) {
        if (ap.wep)
            findings.push_back("[WEP]  BSSID: " + ap.bssid + "  SSID: " + ap.ssid);
        if (ap.tkip)
            findings.push_back("[TKIP] BSSID: " + ap.bssid + "  SSID: " + ap.ssid);
        if (ap.wps)
            findings.push_back("[WPS]  BSSID: " + ap.bssid + "  SSID: " + ap.ssid);
    }
    return findings;
}

std::vector<std::string> runWirelessInfo() {
    std::vector<std::string> output;

    std::vector<std::string> basic = wifiScan();
    output.insert(output.end(), basic.begin(), basic.end());

    std::string iface = detectWifiInterface();
    std::vector<std::string> weakAPs = scanWeakAPs(iface);
    output.insert(output.end(), weakAPs.begin(), weakAPs.end());

    std::vector<std::string> creds = savedNetworkCreds();
    output.insert(output.end(), creds.begin(), creds.end());

    return output;
}

int main() {
    std::vector<std::string> wirelessResults = runWirelessInfo();
    for (const auto& entry : wirelessResults) {
        if (entry.find("[WEP]") != std::string::npos ||
            entry.find("[TKIP]") != std::string::npos ||
            entry.find("[WPS]") != std::string::npos) {
            std::cout << YELLOW << entry << RESET << "\n";
        } else {
            std::cout << entry << "\n";
        }
    }
    return 0;
}
