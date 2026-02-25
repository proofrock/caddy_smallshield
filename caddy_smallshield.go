package caddy_smallshield

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/proofrock/caddy_smallshield/ipsearch"
	"go.uber.org/zap"
)

const VERSION = "v0.4.0"

func init() {
	caddy.RegisterModule(CaddySmallShield{})
	httpcaddyfile.RegisterHandlerDirective("caddy_smallshield", parseCaddyfile)
}

type CaddySmallShield struct {
	BlacklistURL string `json:"blacklist_url,omitempty"`
	Whitelist    string `json:"whitelist,omitempty"`
	LogBlockings string `json:"log_blockings,omitempty"`

	blacklistCidrs *ipsearch.IPSearch
	whitelist      []string
	logBlockings   bool

	logger *zap.Logger

	mutexForBlacklist *sync.RWMutex
	mutexForWhitelist *sync.RWMutex
}

func (CaddySmallShield) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_smallshield",
		New: func() caddy.Module { return new(CaddySmallShield) },
	}
}

func (m *CaddySmallShield) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	m.mutexForBlacklist = &sync.RWMutex{}
	m.mutexForWhitelist = &sync.RWMutex{}

	m.mutexForBlacklist.Lock()
	defer m.mutexForBlacklist.Unlock()

	if m.BlacklistURL != "" {
		cidrs, err := ipsearch.NewFromURL(m.BlacklistURL, false)
		if err != nil {
			return err
		}
		m.blacklistCidrs = cidrs
	} else {
		m.blacklistCidrs = ipsearch.Empty()
	}

	m.mutexForWhitelist.Lock()
	defer m.mutexForWhitelist.Unlock()

	if m.Whitelist != "" {
		m.whitelist = strings.Split(m.Whitelist, ",")
	}

	if m.LogBlockings != "" {
		lb, err := strconv.ParseBool(m.LogBlockings)
		if err != nil {
			return fmt.Errorf("'%s' is not a valid config for log_blockings", m.LogBlockings)
		}
		m.logBlockings = lb
	}

	loggingString := ""
	if m.logBlockings {
		loggingString = " Logging active."
	}
	m.logger.Sugar().Infof("SmallShield %s: init'd with %d items in blacklist and %d in whitelist.%s", VERSION, m.blacklistCidrs.IPRangesIngested(), len(m.whitelist), loggingString)

	// return fmt.Errorf("myerror")
	return nil
}

func (m *CaddySmallShield) IsBlacklisted(ip string) bool {
	if ip == "" {
		return false // Invalid IP TODO check for integrity
	}
	m.mutexForBlacklist.RLock()
	defer m.mutexForBlacklist.RUnlock()
	ret, err := m.blacklistCidrs.CheckIP(ip)
	if err != nil {
		m.logger.Error(fmt.Sprintf("error in checking IP %s", ip))
		return true
	}
	return ret
}

func (m *CaddySmallShield) IsWhitelisted(ip string) bool {
	m.mutexForWhitelist.RLock()
	defer m.mutexForWhitelist.RUnlock()
	return slices.Contains(m.whitelist, ip)
}

func (m CaddySmallShield) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	blockedReason := ""

	var ip = cutToColon(r.RemoteAddr)
	m.logger.Sugar().Infof("IP: %s", r.RemoteAddr)
	if m.IsBlacklisted(ip) && !m.IsWhitelisted(ip) {
		blockedReason = fmt.Sprintf("IP %s is blocked", ip)
	}

	if blockedReason != "" {
		if m.logBlockings {
			m.logger.Sugar().Infof("blocked: %s", blockedReason)
		}
		return caddyhttp.Error(403, errors.New(blockedReason))
	}
	return next.ServeHTTP(w, r)
}

func (m *CaddySmallShield) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "whitelist":
				if !d.Args(&m.Whitelist) {
					return d.Err("invalid whitelist configuration")
				}
			case "blacklist_url":
				if !d.Args(&m.BlacklistURL) {
					return d.Err("invalid blacklist_url configuration")
				}
			case "log_blockings":
				if !d.Args(&m.LogBlockings) {
					return d.Err("invalid log_blockings configuration")
				}
			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddySmallShield
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// func (m *CaddySmallShield) Validate() error {
// 	if m.whitelist == nil {
// 		return fmt.Errorf("no whitelist")
// 	}
// 	if m.blacklist == nil {
// 		return fmt.Errorf("no whitelist")
// 	}
// 	return nil
// }

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddySmallShield)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddySmallShield)(nil)
	_ caddyfile.Unmarshaler       = (*CaddySmallShield)(nil)
	// _ caddy.Validator             = (*CaddySmallShield)(nil)
)
