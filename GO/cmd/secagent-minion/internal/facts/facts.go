// Package facts collecte les facts système de l'agent.
//
// Les facts sont envoyés au relay server lors de l'enrollment (POST /api/register)
// et exposés à Ansible via le module setup (gather_facts).
//
// Implémentation :
//   - Dépendance optionnelle : github.com/shirou/gopsutil/v3
//     Si non disponible → fallback stdlib uniquement
//   - Graceful degradation : chaque collecte est indépendante,
//     une erreur partielle retourne les facts disponibles
//   - Stdlib uniquement pour les informations critiques (hostname, OS, kernel)
//
// Facts collectés :
//   - hostname         : socket.gethostname()
//   - os               : {system, release, version}
//   - os_family        : Debian|RedHat|Suse|Arch|Alpine|Gentoo|Linux|Windows
//   - kernel_version   : uname -r
//   - cpu_count        : nombre de vCPUs
//   - memory_total_mb  : RAM totale en MB
//   - disk_total_gb    : espace disque total en GB
//   - ip_addresses     : liste des IPs non-loopback
//   - network_interfaces : [{name, mac, ipv4, ipv6}]
//   - python_version   : non applicable en GO → "N/A"
//   - packages         : {} (non implémenté dans cette version)
package facts

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Facts contient les informations système collectées.
type Facts struct {
	Hostname          string            `json:"hostname"`
	OS                OSInfo            `json:"os"`
	OSFamily          string            `json:"os_family"`
	KernelVersion     string            `json:"kernel_version"`
	CPUCount          int               `json:"cpu_count"`
	MemoryTotalMB     int               `json:"memory_total_mb"`
	DiskTotalGB       float64           `json:"disk_total_gb"`
	IPAddresses       []string          `json:"ip_addresses"`
	NetworkInterfaces []NetworkIface    `json:"network_interfaces"`
	PythonVersion     string            `json:"python_version"`
	Packages          map[string]string `json:"packages"`
}

// OSInfo contient les informations sur le système d'exploitation.
type OSInfo struct {
	System  string `json:"system"`
	Release string `json:"release"`
	Version string `json:"version"`
}

// NetworkIface décrit une interface réseau.
type NetworkIface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

// Collect retourne les facts système avec graceful degradation.
// Chaque champ est collecté indépendamment — une erreur partielle
// laisse les autres champs renseignés.
func Collect() Facts {
	return Facts{
		Hostname:          getHostname(),
		OS:                getOSInfo(),
		OSFamily:          getOSFamily(),
		KernelVersion:     getKernelVersion(),
		CPUCount:          getCPUCount(),
		MemoryTotalMB:     getMemoryTotalMB(),
		DiskTotalGB:       getDiskTotalGB(),
		IPAddresses:       getNonLoopbackIPs(),
		NetworkInterfaces: getNetworkInterfaces(),
		PythonVersion:     "N/A",
		Packages:          map[string]string{},
	}
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func getOSInfo() OSInfo {
	info := OSInfo{
		System:  runtime.GOOS,
		Release: "",
		Version: "",
	}

	// Linux : lit /etc/os-release
	if runtime.GOOS == "linux" {
		data := readFileLines("/etc/os-release")
		kv := parseKeyValue(data)
		if v, ok := kv["VERSION_ID"]; ok {
			info.Release = strings.Trim(v, `"`)
		}
		if v, ok := kv["VERSION"]; ok {
			info.Version = strings.Trim(v, `"`)
		}
	}

	return info
}

func getOSFamily() string {
	if runtime.GOOS == "windows" {
		return "Windows"
	}
	if runtime.GOOS != "linux" {
		return runtime.GOOS
	}

	data := readFileLines("/etc/os-release")
	kv := parseKeyValue(data)

	// Priorité : ID_LIKE → ID
	for _, key := range []string{"ID_LIKE", "ID"} {
		raw, ok := kv[key]
		if !ok {
			continue
		}
		val := strings.ToLower(strings.Trim(raw, `"`))
		for _, part := range strings.Fields(val) {
			switch part {
			case "debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian":
				return "Debian"
			case "rhel", "centos", "fedora", "rocky", "almalinux", "ol", "scientific":
				return "RedHat"
			case "suse", "opensuse", "sles":
				return "Suse"
			case "arch", "manjaro", "endeavouros":
				return "Arch"
			case "alpine":
				return "Alpine"
			case "gentoo":
				return "Gentoo"
			}
		}
	}

	return "Linux"
}

func getKernelVersion() string {
	out, err := runCmd("uname", "-r")
	if err != nil {
		return runtime.Version() // fallback : version Go (informatif)
	}
	return strings.TrimSpace(out)
}

func getCPUCount() int {
	n := runtime.NumCPU()
	if n < 0 {
		return 0
	}
	return n
}

func getMemoryTotalMB() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	lines := readFileLines("/proc/meminfo")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kb, err := strconv.Atoi(parts[1])
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

func getDiskTotalGB() float64 {
	// Stat du filesystem racine
	var paths []string
	if runtime.GOOS == "windows" {
		paths = []string{"C:\\"}
	} else {
		paths = []string{"/"}
	}

	for _, p := range paths {
		total, err := diskTotalBytes(p)
		if err == nil && total > 0 {
			return roundFloat(float64(total)/float64(1<<30), 2)
		}
	}
	return 0
}

func getNonLoopbackIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var result []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				result = append(result, s)
			}
		}
	}
	return result
}

func getNetworkInterfaces() []NetworkIface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []NetworkIface
	for _, iface := range ifaces {
		if iface.Name == "lo" || strings.HasPrefix(iface.Name, "lo:") {
			continue
		}
		ni := NetworkIface{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				s := ip.String()
				if ip.To4() != nil {
					ni.IPv4 = append(ni.IPv4, s)
				} else {
					ni.IPv6 = append(ni.IPv6, s)
				}
			}
		}
		result = append(result, ni)
	}
	return result
}

// --- Helpers ---

func readFileLines(path string) []string {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func parseKeyValue(lines []string) map[string]string {
	kv := make(map[string]string)
	for _, line := range lines {
		if idx := strings.IndexByte(line, '='); idx > 0 {
			kv[line[:idx]] = line[idx+1:]
		}
	}
	return kv
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func roundFloat(f float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int(f*pow+0.5)) / pow
}

// diskTotalBytes retourne la taille totale du filesystem en bytes via statfs.
// Implémenté dans des fichiers platform-specific (_linux.go, _windows.go, _other.go).
func diskTotalBytes(path string) (uint64, error) {
	return diskTotalBytesOS(path)
}

// fallback for compilation — real impl in platform files
var _ = fmt.Sprintf // avoid unused import
