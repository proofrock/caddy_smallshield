package caddy_smallshield

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strings"
)

func ExtractIPRange(line string) *net.IPNet {
	cidrRegex := regexp.MustCompile(`\b(\d{1,3}(\.\d{1,3}){3}/\d{1,2})\b`)
	ipRegex := regexp.MustCompile(`\b(\d{1,3}(\.\d{1,3}){3})\b`)

	// Check for CIDR range first
	if cidrMatch := cidrRegex.FindString(line); cidrMatch != "" {
		_, ipNet, err := net.ParseCIDR(cidrMatch)
		if err == nil {
			return ipNet
		}
	}

	// Check for single IP
	if ipMatch := ipRegex.FindString(line); ipMatch != "" {
		ip := net.ParseIP(ipMatch)
		if ip != nil {
			// Convert single IP to CIDR (e.g., /32)
			if strings.Contains(ip.String(), ".") { // IPv4
				return &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				}
			}
		}
	}

	// No valid IP or CIDR range found
	return nil
}

func NewIPBlacklist(filename string) ([]*net.IPNet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cidrs []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cidr := ExtractIPRange(scanner.Text())
		if cidr != nil {
			cidrs = append(cidrs, cidr)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cidrs, nil
}

func CutToColon(input string) string {
	index := strings.Index(input, ":")

	if index != -1 {
		return input[:index]
	}
	return input
}
