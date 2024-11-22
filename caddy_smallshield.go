package caddy_smallshield

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/proofrock/caddy_smallshield/iptree"
	"go.uber.org/zap"
)

const VERSION = "v0.1.0"

func init() {
	caddy.RegisterModule(CaddySmallShield{})
	httpcaddyfile.RegisterHandlerDirective("caddy_smallshield", parseCaddyfile)
}

type CaddySmallShield struct {
	BlacklistURL string `json:"blacklist_url,omitempty"`
	Whitelist    string `json:"whitelist,omitempty"`

	blacklistCidrs *iptree.IPTree
	whitelist      []string

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
		cidrs, err := iptree.NewFromURL(m.BlacklistURL, false)
		if err != nil {
			return err
		}
		m.blacklistCidrs = cidrs
	}

	m.mutexForWhitelist.Lock()
	defer m.mutexForWhitelist.Unlock()

	if m.Whitelist != "" {
		m.whitelist = strings.Split(m.Whitelist, ",")
	}

	m.logger.Sugar().Infof("SmallShield %s: init'd with %d items in blacklist and %d in whitelist", VERSION, m.blacklistCidrs.IPRangesIngested(), len(m.whitelist))

	// return fmt.Errorf("myerror")
	return nil
}

func (m *CaddySmallShield) IsBlacklisted(ip string) bool {
	if ip == "" {
		return false // Invalid IP TODO check for integrity
	}
	m.mutexForBlacklist.RLock()
	defer m.mutexForBlacklist.RUnlock()
	return m.blacklistCidrs.CheckIP(ip)
}

func (m *CaddySmallShield) IsWhitelisted(ip string) bool {
	m.mutexForWhitelist.RLock()
	defer m.mutexForWhitelist.RUnlock()
	return slices.Contains[[]string](m.whitelist, ip)
}

func cutToColon(input string) string {
	index := strings.Index(input, ":")

	if index != -1 {
		return input[:index]
	}
	return input
}

func (m CaddySmallShield) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var ip = cutToColon(r.RemoteAddr)
	if m.IsWhitelisted(ip) || !m.IsBlacklisted(ip) {
		return next.ServeHTTP(w, r)
	}
	return caddyhttp.Error(403, errors.New("IP Blocked"))
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
