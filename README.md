# Caddy Small Shield

> 5 gp, 3 lbs, AC +1

A Caddy middleware that filters requests by IP using a **policy chain**: an ordered list of IP sets, each with configurable outcomes depending on whether the client IP is found or not.

Works with IPv4. Files are loaded at startup.

---

## How it works

The middleware evaluates each list in order:

1. Look up the client IP in the list.
2. If the IP **is** in the list and `if_ip_in_list` is set → return that status code immediately.
3. If the IP **is not** in the list and `if_ip_not_in_list` is set → return that status code immediately.
4. If neither branch matches → continue to the next list.
5. If all lists are exhausted without a decision → pass the request through (200).

A status code of `200` means "pass through to Caddy". Any other code (typically `403`) blocks the request.

### Example walkthrough

```caddyfile
lists {
    entry {
        file "whitelist"
        if_ip_in_list 200
    }
    entry {
        file "it-aggregated.zone" # https://www.ipdeny.com/ipblocks/data/aggregated/it-aggregated.zone
        if_ip_not_in_list 403
    }
    entry {
        file "firehol_level1.netset" # https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset
        if_ip_in_list 403
        if_ip_not_in_list 200
    }
}
```

| Client IP           | List 1 (whitelist) | List 2 (Italy)   | List 3 (threats) | Result  |
| ------------------- | ------------------ | ---------------- | ---------------- | ------- |
| In whitelist        | in → **200**       | —                | —                | ✅ pass  |
| Italian, clean      | not in → skip      | in → skip        | not in → **200** | ✅ pass  |
| Italian, in threats | not in → skip      | in → skip        | in → **403**     | ❌ block |
| Non-Italian         | not in → skip      | not in → **403** | —                | ❌ block |

---

## List file format

Each file contains one IP address or CIDR range per line. The parser scans each line for an IP or CIDR pattern, so comment text on the same line is allowed.

Lines beginning with `#` and blank lines are skipped.

```
# example list
10.0.0.0/8
172.16.0.0/12
192.168.1.42           # bare IP, treated as /32
1.2.3.0/24  ; some note about this range
```

Supported formats per line:
- CIDR notation: `1.2.3.0/24`
- Single IP: `1.2.3.4` (treated as `1.2.3.4/32`)
- Any of the above embedded in a line of text (e.g. a comment before/after)

---

## Configuration

```caddyfile
{
    order caddy_smallshield first
}

:8089 {
    caddy_smallshield {
        log_blockings "1"
        lists {
            entry {
                file "path/to/whitelist"
                if_ip_in_list 200
            }
            entry {
                file "path/to/it-aggregated.zone"
                if_ip_not_in_list 403
            }
            entry {
                file "path/to/firehol_level1.netset"
                if_ip_in_list 403
                if_ip_not_in_list 200
            }
        }
    }
    respond "Hello, World!"
}
```

### Directives

**`log_blockings`** (`"0"` / `"1"`, default `"0"`)
When enabled, logs every blocked request to Caddy's `info` channel.

**`when_ipv6`** (status code, optional)
Action for IPv6 clients, which cannot be looked up in IPv4 lists. If omitted, IPv6 requests pass through. Set to `403` to block them, or `200` to explicitly allow them (same as omitting). Setting 200/not setting effectively disables the rules engine.

**`lists { ... }`**
Ordered list of IP sets. Each entry is an `entry { }` block with:

| Field                      | Required | Description                                              |
| -------------------------- | -------- | -------------------------------------------------------- |
| `file <path>`              | yes      | Path to the IP list file (relative to working directory) |
| `if_ip_in_list <code>`     | no       | Status code to return if IP **is** in the list           |
| `if_ip_not_in_list <code>` | no       | Status code to return if IP **is not** in the list       |

At least one of `if_ip_in_list` / `if_ip_not_in_list` should be set, otherwise the entry has no effect.

---

## Building

```bash
xcaddy build --with github.com/proofrock/caddy_smallshield
```

---

## Running locally

```bash
xcaddy run --config Caddyfile
```

```bash
curl -v localhost:8089 # 200 OK
curl -v localhost:8090 # 200 OK
```

---

## Performance

IP lookup uses a **sorted array of merged intervals + binary search** (O(log n)). Overlapping and adjacent ranges are merged at load time, so the search structure is typically much smaller than the raw list. A list of 100 000 ranges usually reduces to a few thousand merged intervals.
