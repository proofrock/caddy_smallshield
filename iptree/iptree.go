package iptree

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Implements a decision tree for IP ranges. You feed it with IPv4 ranges ("192.168.1.2/24")
// and check if a single IP belongs to any. It does it efficiently (~4000 IP ranges are stored
// in less than 1Mb) and quickly (one lookup is < 0.5μs).
// It's optionally thread safe BUT it doesn't check for format correctedness, if you pass invalid
// strings it will fail spectacularly or - worse - silently.

type node struct {
	children [2]*node
	level    int
	isRange  bool
}

type IPTree struct {
	root       node
	iptotal    int
	threadSafe bool

	mutex *sync.RWMutex
}

func NewIPTree(threadSafe bool) *IPTree {
	ret := IPTree{
		root:       node{level: 0},
		threadSafe: threadSafe,
	}
	if threadSafe {
		ret.mutex = &sync.RWMutex{}
	}
	return &ret
}

var bitmasks = [...]int{128, 64, 32, 16, 8, 4, 2, 1}

func bit(num int, pos int) int {
	ret := num & bitmasks[pos]
	if ret == 0 {
		return 0
	}
	return 1
}

func (ipt *IPTree) ingest(rangip string) error {
	splitBySlash := strings.Split(rangip, "/")
	splitByDot := strings.Split(splitBySlash[0], ".")
	rangePart, err := strconv.Atoi(splitBySlash[1])
	if err != nil {
		return err
	}
	var ipParts [4]int
	for i := 0; i < 4; i++ {
		ipParts[i], err = strconv.Atoi(splitByDot[i])
		if err != nil {
			return err
		}
	}
	pos := 1
	current := &ipt.root
all:
	for ipPart := 0; ipPart < 4; ipPart++ {
		for bitPos := 0; bitPos < 8; bitPos++ {
			if current.isRange {
				break all
			}
			if rangePart == current.level {
				current.isRange = true
				current.children = [2]*node{nil, nil}
				break all
			}
			myBit := bit(ipParts[ipPart], bitPos)
			if current.children[myBit] == nil {
				current.children[myBit] = &node{level: pos}
			}
			current = current.children[myBit]
			pos++
		}
	}
	ipt.iptotal++
	return nil
}

func (ipt *IPTree) AddIPRange(rangip string) error {
	if ipt.threadSafe {
		ipt.mutex.Lock()
		defer ipt.mutex.Unlock()
	}
	return ipt.ingest(rangip)
}

func (ipt IPTree) CheckIP(ip string) (bool, error) {
	if ipt.threadSafe {
		ipt.mutex.RLock()
		defer ipt.mutex.RUnlock()
	}

	splitByDot := strings.Split(ip, ".")
	var ipParts [4]int
	for i := 0; i < 4; i++ {
		ipPart, err := strconv.Atoi(splitByDot[i])
		if err != nil {
			return false, err
		}
		ipParts[i] = ipPart
	}
	current := &ipt.root
	for ipPart := 0; ipPart < 4; ipPart++ {
		for bitPos := 0; bitPos < 8; bitPos++ {
			if current.isRange {
				return true, nil
			}
			myBit := bit(ipParts[ipPart], bitPos)
			if current.children[myBit] == nil {
				return false, nil
			}
			current = current.children[myBit]
		}
	}
	return true, nil
}

// O(log(n))
func (ipt IPTree) NodesNumber() int {
	if ipt.threadSafe {
		ipt.mutex.RLock()
		defer ipt.mutex.RUnlock()
	}

	var subtreeCount func(node) int
	subtreeCount = func(nd node) int {
		ret := 1
		if nd.children[0] != nil {
			ret += subtreeCount(*nd.children[0])
		}
		if nd.children[1] != nil {
			ret += subtreeCount(*nd.children[1])
		}
		return ret
	}
	return subtreeCount(ipt.root)
}

// O(1)
func (ipt IPTree) IPRangesIngested() int {
	if ipt.threadSafe {
		ipt.mutex.RLock()
		defer ipt.mutex.RUnlock()
	}

	return ipt.iptotal
}

var cidrRegex *regexp.Regexp = regexp.MustCompile(`\b(\d{1,3}(\.\d{1,3}){3}/\d{1,2})\b`)
var ipRegex *regexp.Regexp = regexp.MustCompile(`\b(\d{1,3}(\.\d{1,3}){3})\b`)

func line2IPRange(line string) string {
	// Check for CIDR range first
	if cidrMatch := cidrRegex.FindString(line); cidrMatch != "" {
		return cidrMatch
	}

	// Check for single IP
	if ipMatch := ipRegex.FindString(line); ipMatch != "" {
		return ipMatch + "/32"
	}

	return ""
}

func Empty() *IPTree {
	return NewIPTree(false)
}

func NewFromURL(url string, threadSafe bool) (*IPTree, error) {
	lines, err := fetchBodyLinesWithRetries(url)
	if err != nil {
		return nil, err
	}

	ipt := NewIPTree(threadSafe)
	if ipt.threadSafe {
		ipt.mutex.Lock()
		defer ipt.mutex.Unlock()
	}
	for _, cidr := range lines {
		if strings.HasPrefix(cidr, ";") || strings.HasPrefix(cidr, "#") {
			continue
		}
		cidr = line2IPRange(cidr)
		if cidr != "" {
			err := ipt.ingest(cidr)
			if err != nil {
				// TODO silent? I cannot let it stop everything
			}
		}
	}

	return ipt, nil
}
