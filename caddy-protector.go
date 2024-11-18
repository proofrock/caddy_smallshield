package caddy_smallshield

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddySmallShield{})
	httpcaddyfile.RegisterHandlerDirective("caddy_smallshield", parseCaddyfile)
}

type CaddySmallShield struct {
	BlacklistFile string `json:"blacklist_file,omitempty"`
	Whitelist     string `json:"whitelist,omitempty"`

	blacklistCidrs []*net.IPNet
	whitelist      []string

	logger *zap.Logger

	cache             *sync.Map
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

	m.cache = &sync.Map{}
	m.mutexForBlacklist = &sync.RWMutex{}
	m.mutexForWhitelist = &sync.RWMutex{}

	m.cache.Clear()

	m.mutexForBlacklist.Lock()
	defer m.mutexForBlacklist.Unlock()

	if m.BlacklistFile != "" {
		cidrs, err := NewIPBlacklist(m.BlacklistFile)
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

	m.logger.Sugar().Infof("caddy_smallshield: init'd with %d items in blacklist and %d in whitelist", len(m.blacklistCidrs), len(m.whitelist))

	// return fmt.Errorf("myerror")
	return nil
}

func (m *CaddySmallShield) IsBlacklisted(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false // Invalid IP
	}
	m.mutexForBlacklist.RLock()
	defer m.mutexForBlacklist.RUnlock()
	for _, cidr := range m.blacklistCidrs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func (m *CaddySmallShield) IsWhitelisted(ip string) bool {
	m.mutexForWhitelist.RLock()
	defer m.mutexForWhitelist.RUnlock()
	return slices.Contains[[]string](m.whitelist, ip)
}

func (m CaddySmallShield) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var ip = CutToColon(r.RemoteAddr)
	ok, cached := m.cache.Load(ip)
	if !cached {
		ok = m.IsWhitelisted(ip) || !m.IsBlacklisted(ip)
		m.cache.Store(ip, ok)
	}
	println(ip)
	println(ok.(bool))
	if ok.(bool) {
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
			case "blacklist_file":
				if !d.Args(&m.BlacklistFile) {
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
