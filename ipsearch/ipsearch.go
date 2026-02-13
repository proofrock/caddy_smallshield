package ipsearch

import (
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Using sorted intervals + binary search.
// Optimized for build-once-query-many: all ranges are sorted and merged on first
// lookup (or after any mutation), then queries use binary search on a flat array.

type interval struct {
	lo, hi uint32
}

type IPSearch struct {
	pending    []interval
	ranges     []interval
	iptotal    int
	built      bool
	threadSafe bool
	mutex      *sync.RWMutex
}

func NewIPTree(threadSafe bool) *IPSearch {
	ret := &IPSearch{}
	ret.threadSafe = threadSafe
	if threadSafe {
		ret.mutex = &sync.RWMutex{}
	}
	return ret
}

func parseCIDR(rangip string) (uint32, uint32, error) {
	parts := strings.Split(rangip, "/")
	dotParts := strings.Split(parts[0], ".")
	prefix, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, err
	}
	var ip uint32
	for i := 0; i < 4; i++ {
		v, err := strconv.Atoi(dotParts[i])
		if err != nil {
			return 0, 0, err
		}
		ip = (ip << 8) | uint32(v)
	}
	mask := uint32(0xFFFFFFFF) << uint(32-prefix)
	lo := ip & mask
	hi := lo | ^mask
	return lo, hi, nil
}

func parseIP(ip string) (uint32, error) {
	parts := strings.Split(ip, ".")
	var result uint32
	for i := 0; i < 4; i++ {
		v, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, err
		}
		result = (result << 8) | uint32(v)
	}
	return result, nil
}

func (ipt *IPSearch) build() {
	sort.Slice(ipt.pending, func(i, j int) bool {
		return ipt.pending[i].lo < ipt.pending[j].lo
	})
	ipt.ranges = ipt.ranges[:0]
	for _, r := range ipt.pending {
		if len(ipt.ranges) > 0 {
			last := &ipt.ranges[len(ipt.ranges)-1]
			if r.lo <= last.hi+1 {
				if r.hi > last.hi {
					last.hi = r.hi
				}
				continue
			}
		}
		ipt.ranges = append(ipt.ranges, r)
	}
	ipt.built = true
}

func (ipt *IPSearch) ingest(rangip string) error {
	lo, hi, err := parseCIDR(rangip)
	if err != nil {
		return err
	}
	ipt.pending = append(ipt.pending, interval{lo, hi})
	ipt.iptotal++
	ipt.built = false
	return nil
}

func (ipt *IPSearch) AddIPRange(rangip string) error {
	if ipt.threadSafe {
		ipt.mutex.Lock()
		defer ipt.mutex.Unlock()
	}
	return ipt.ingest(rangip)
}

func (ipt *IPSearch) CheckIP(ip string) (bool, error) {
	if ipt.threadSafe {
		ipt.mutex.RLock()
		if !ipt.built {
			ipt.mutex.RUnlock()
			ipt.mutex.Lock()
			if !ipt.built {
				ipt.build()
			}
			ipt.mutex.Unlock()
			ipt.mutex.RLock()
		}
		defer ipt.mutex.RUnlock()
	} else if !ipt.built {
		ipt.build()
	}

	ipVal, err := parseIP(ip)
	if err != nil {
		return false, err
	}

	i := sort.Search(len(ipt.ranges), func(i int) bool {
		return ipt.ranges[i].hi >= ipVal
	})
	if i < len(ipt.ranges) && ipt.ranges[i].lo <= ipVal {
		return true, nil
	}
	return false, nil
}

// Returns the number of merged intervals (equivalent to NodesNumber in iptree).
func (ipt *IPSearch) NodesNumber() int {
	if ipt.threadSafe {
		ipt.mutex.RLock()
		defer ipt.mutex.RUnlock()
	}
	if !ipt.built {
		return len(ipt.pending)
	}
	return len(ipt.ranges)
}

func (ipt *IPSearch) IPRangesIngested() int {
	if ipt.threadSafe {
		ipt.mutex.RLock()
		defer ipt.mutex.RUnlock()
	}
	return ipt.iptotal
}

var cidrRegex *regexp.Regexp = regexp.MustCompile(`\b(\d{1,3}(\.\d{1,3}){3}/\d{1,2})\b`)
var ipRegex *regexp.Regexp = regexp.MustCompile(`\b(\d{1,3}(\.\d{1,3}){3})\b`)

func line2IPRange(line string) string {
	if cidrMatch := cidrRegex.FindString(line); cidrMatch != "" {
		return cidrMatch
	}
	if ipMatch := ipRegex.FindString(line); ipMatch != "" {
		return ipMatch + "/32"
	}
	return ""
}

func Empty() *IPSearch {
	return NewIPTree(false)
}

func NewFromURL(url string, threadSafe bool) (*IPSearch, error) {
	lines, err := fetchBodyLinesWithRetries(url)
	if err != nil {
		return nil, err
	}

	ipt := NewIPTree(threadSafe)
	for _, cidr := range lines {
		if strings.HasPrefix(cidr, ";") || strings.HasPrefix(cidr, "#") {
			continue
		}
		cidr = line2IPRange(cidr)
		if cidr != "" {
			ipt.ingest(cidr)
		}
	}
	ipt.build()

	return ipt, nil
}

// for ipflat.go

const retriesNumber int = 3
const retryPause time.Duration = 2 * time.Second

func fetchBodyLines(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch URL, status code: " + resp.Status)
	}
	bbody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(bbody), "\n"), nil
}

func fetchBodyLinesWithRetries(url string) ([]string, error) {
	for i := 0; i < retriesNumber; i++ {
		ret, err := fetchBodyLines(url)
		if err == nil {
			return ret, nil
		}

		if i == retriesNumber-1 { // last retry
			return nil, err
		}

		time.Sleep(retryPause)
	}
	return nil, errors.New("this is impossible")
}
