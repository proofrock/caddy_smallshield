# Caddy Small Shield

> 5 gp, 3 lbs, AC +1

This Caddy module is really simple (for now), it loads a URL containing a blacklist of IPs or IP ranges

```
...
134.122.168.0/24
134.122.188.0/23
137.59.236.0/22
...
```

and filter away requests coming from those IPs.

> In the examples we use [firehol_level1 on github](https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset), please do not abuse their bandwidth.

Also, it allows to specify a comma-separated list of IPs to consider as reputable, despite the blacklist.

It works with IPV4.

It tries to do it as fast as possible, using a high-performance and space-efficient bit tree to calculate
the IP "fate".

The parser of the blacklist looks in each line for a pattern that resembles an IP or an IP range, and loads
it. Lines not containing any are ignored, as lines beginning with `#` or `;` are.

## Building

```bash
xcaddy build --with github.com/proofrock/caddy_smallshield@v0.2.1
```

## Configuration

```caddyfile
{
	order caddy_smallshield first
}

:8089 {
	caddy_smallshield {
		whitelist "127.0.0.1"
		# Please do not abuse, e.g. reloading the config too many times
		blacklist_url "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
	}
	respond "Hello, World!"
}
```