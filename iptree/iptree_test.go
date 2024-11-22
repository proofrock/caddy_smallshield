package iptree_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/proofrock/caddy_smallshield/iptree"
)

func mytest(t *testing.T, threadSafe bool) {
	start := time.Now()
	ipt, err := iptree.NewFromURL("https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset", threadSafe)
	if err != nil {
		panic(err)
	}
	println(fmt.Sprintf("Ingestion of %d IP ranges took %d μs", ipt.IPRangesIngested(), time.Since(start).Microseconds()))
	println("Nodes generated: ", ipt.NodesNumber())
	println("Avg nodes/IP range: ", ipt.NodesNumber()/ipt.IPRangesIngested())

	assert := func(ip string, term bool) {
		if val, _ := ipt.CheckIP(ip); val != term {
			t.Fatalf("%s is not %t", ip, term)
		}
	}

	assert("192.168.45.78", true)   // belongs to 192.168.0.0/16
	assert("10.45.167.89", true)    // belongs to 10.0.0.0/8
	assert("172.16.234.12", true)   // belongs to 172.16.0.0/12
	assert("192.168.1.100", true)   // belongs to 192.168.0.0/16
	assert("169.254.45.67", true)   // belongs to 169.254.0.0/16
	assert("127.0.0.1", true)       // belongs to 127.0.0.0/8
	assert("172.20.45.90", true)    // belongs to 172.16.0.0/12
	assert("172.17.167.234", true)  // belongs to 172.16.0.0/12
	assert("192.168.200.45", true)  // belongs to 192.168.0.0/16
	assert("10.200.45.67", true)    // belongs to 10.0.0.0/8
	assert("172.23.45.89", true)    // belongs to 172.16.0.0/12
	assert("192.168.78.90", true)   // belongs to 192.168.0.0/16
	assert("10.67.89.123", true)    // belongs to 10.0.0.0/8
	assert("172.18.234.56", true)   // belongs to 172.16.0.0/12
	assert("192.168.167.89", true)  // belongs to 192.168.0.0/16
	assert("10.178.45.67", true)    // belongs to 10.0.0.0/8
	assert("172.22.89.90", true)    // belongs to 172.16.0.0/12
	assert("192.168.45.234", true)  // belongs to 192.168.0.0/16
	assert("10.89.167.234", true)   // belongs to 10.0.0.0/8
	assert("172.19.45.67", true)    // belongs to 172.16.0.0/12
	assert("192.168.234.56", true)  // belongs to 192.168.0.0/16
	assert("10.234.56.78", true)    // belongs to 10.0.0.0/8
	assert("172.21.167.89", true)   // belongs to 172.16.0.0/12
	assert("192.168.90.123", true)  // belongs to 192.168.0.0/16
	assert("10.123.234.56", true)   // belongs to 10.0.0.0/8
	assert("172.24.89.90", true)    // belongs to 172.16.0.0/12
	assert("192.168.123.234", true) // belongs to 192.168.0.0/16
	assert("10.156.234.56", true)   // belongs to 10.0.0.0/8
	assert("172.25.167.89", true)   // belongs to 172.16.0.0/12
	assert("192.168.167.234", true) // belongs to 192.168.0.0/16
	assert("10.189.234.56", true)   // belongs to 10.0.0.0/8
	assert("172.26.89.90", true)    // belongs to 172.16.0.0/12
	assert("233.234.56.78", true)   // belongs to 224.0.0.0/3
	assert("244.167.89.90", true)   // belongs to 224.0.0.0/3
	assert("255.234.56.78", true)   // belongs to 224.0.0.0/3
	assert("2.57.168.2", true)      // belongs to 2.57.168.0/24

	assert("11.45.167.89", false)
	assert("15.234.56.78", false)
	assert("25.167.89.90", false)
	assert("35.234.56.78", false)
	assert("44.167.89.90", false)
	assert("55.234.56.78", false)
	assert("66.167.89.90", false)
	assert("75.234.56.78", false)
	assert("88.167.89.90", false)
	assert("99.234.56.78", false)
	assert("111.167.89.90", false)
	assert("122.234.56.78", false)
	assert("133.167.89.90", false)
	assert("144.234.56.78", false)
	assert("155.167.89.90", false)
	assert("166.234.56.78", false)
	assert("177.167.89.90", false)
	assert("188.234.56.78", false)
	assert("199.167.89.90", false)
	assert("211.234.56.78", false)
	assert("222.167.89.90", false)
	assert("12.167.89.90", false)
	assert("13.234.56.78", false)
	assert("14.167.89.90", false)
	assert("16.234.56.78", false)
	assert("17.167.89.90", false)
	assert("18.234.56.78", false)
	assert("19.167.89.90", false)
	assert("20.234.56.78", false)
	assert("2.58.168.2", false)

	start = time.Now()
	for range 10000000 {
		_, _ = ipt.CheckIP("2.57.168.2")
		_, _ = ipt.CheckIP("2.58.168.2")
	}
	println(fmt.Sprintf("Over 10M iterations of 2 checks, a single check took %f ns", float64(time.Since(start).Microseconds())/20000))
}

func TestThreadSafe(t *testing.T) {
	mytest(t, true)
}

func TestThreadUnSafe(t *testing.T) {
	mytest(t, false)
}
