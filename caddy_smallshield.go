package caddy_smallshield

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/proofrock/caddy_smallshield/ipsearch"
	"go.uber.org/zap"
)

const VERSION = "v0.5.0"

func init() {
	caddy.RegisterModule(CaddySmallShield{})
	httpcaddyfile.RegisterHandlerDirective("caddy_smallshield", parseCaddyfile)
}

// ListEntry is one step in the policy chain. The IP is looked up in the list
// loaded from File; depending on the result, the corresponding status code is
// returned immediately, or evaluation continues to the next entry.
type ListEntry struct {
	File        string `json:"file"`
	IfInList    *int   `json:"if_ip_in_list,omitempty"`
	IfNotInList *int   `json:"if_ip_not_in_list,omitempty"`

	cidrs *ipsearch.IPSearch // populated at Provision time, not serialised
}

type CaddySmallShield struct {
	Lists        []ListEntry `json:"lists,omitempty"`
	LogBlockings string      `json:"log_blockings,omitempty"`
	WhenIPv6     string      `json:"when_ipv6,omitempty"`

	logBlockings bool
	whenIPv6     *int // nil = pass through (default)
	logger       *zap.Logger
}

func (CaddySmallShield) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_smallshield",
		New: func() caddy.Module { return new(CaddySmallShield) },
	}
}

func (m *CaddySmallShield) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	for i := range m.Lists {
		cidrs, err := ipsearch.NewFromFile(m.Lists[i].File, false)
		if err != nil {
			return fmt.Errorf("list %d (%s): %w", i, m.Lists[i].File, err)
		}
		m.Lists[i].cidrs = cidrs
	}

	if m.LogBlockings != "" {
		lb, err := strconv.ParseBool(m.LogBlockings)
		if err != nil {
			return fmt.Errorf("'%s' is not a valid config for log_blockings", m.LogBlockings)
		}
		m.logBlockings = lb
	}

	if m.WhenIPv6 != "" {
		code, err := strconv.Atoi(m.WhenIPv6)
		if err != nil {
			return fmt.Errorf("'%s' is not a valid status code for when_ipv6", m.WhenIPv6)
		}
		m.whenIPv6 = &code
	}

	m.logger.Sugar().Infof("SmallShield %s: init'd with %d lists", VERSION, len(m.Lists))
	return nil
}

func (m CaddySmallShield) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := extractIP(r.RemoteAddr)

	// IPv6 addresses cannot be looked up in IPv4 lists: apply when_ipv6 policy.
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		if m.whenIPv6 == nil || *m.whenIPv6 == http.StatusOK {
			return next.ServeHTTP(w, r)
		}
		reason := fmt.Sprintf("IPv6 address %s rejected by when_ipv6 policy", ip)
		if m.logBlockings {
			m.logger.Sugar().Infof("blocked: %s", reason)
		}
		return caddyhttp.Error(*m.whenIPv6, errors.New(reason))
	}

	for _, list := range m.Lists {
		inList, err := list.cidrs.CheckIP(ip)
		if err != nil {
			m.logger.Error(fmt.Sprintf("error checking IP %s: %v", ip, err))
			continue
		}

		var code *int
		if inList {
			code = list.IfInList
		} else {
			code = list.IfNotInList
		}

		if code == nil {
			continue // no branch for this outcome, try next list
		}

		if *code == http.StatusOK {
			return next.ServeHTTP(w, r)
		}

		reason := fmt.Sprintf("IP %s rejected by list %s", ip, list.File)
		if m.logBlockings {
			m.logger.Sugar().Infof("blocked: %s", reason)
		}
		return caddyhttp.Error(*code, errors.New(reason))
	}

	// All lists exhausted without a decision: pass through.
	return next.ServeHTTP(w, r)
}

func (m *CaddySmallShield) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "log_blockings":
				if !d.Args(&m.LogBlockings) {
					return d.Err("invalid log_blockings configuration")
				}
			case "when_ipv6":
				if !d.Args(&m.WhenIPv6) {
					return d.Err("missing value for 'when_ipv6'")
				}
			case "lists":
				for d.NextBlock(1) {
					if d.Val() != "entry" {
						return d.Errf("expected 'entry', got '%s'", d.Val())
					}
					var entry ListEntry
					for d.NextBlock(2) {
						switch d.Val() {
						case "file":
							if !d.Args(&entry.File) {
								return d.Err("missing value for 'file'")
							}
						case "if_ip_in_list":
							var s string
							if !d.Args(&s) {
								return d.Err("missing value for 'if_ip_in_list'")
							}
							code, err := strconv.Atoi(s)
							if err != nil {
								return d.Errf("invalid status code for 'if_ip_in_list': %s", s)
							}
							entry.IfInList = &code
						case "if_ip_not_in_list":
							var s string
							if !d.Args(&s) {
								return d.Err("missing value for 'if_ip_not_in_list'")
							}
							code, err := strconv.Atoi(s)
							if err != nil {
								return d.Errf("invalid status code for 'if_ip_not_in_list': %s", s)
							}
							entry.IfNotInList = &code
						default:
							return d.Errf("unknown list entry directive: %s", d.Val())
						}
					}
					if entry.File == "" {
						return d.Err("list entry is missing 'file'")
					}
					m.Lists = append(m.Lists, entry)
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

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddySmallShield)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddySmallShield)(nil)
	_ caddyfile.Unmarshaler       = (*CaddySmallShield)(nil)
)
