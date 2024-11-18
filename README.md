# Caddy Small Shield

> 5 gp, 3 lbs, AC +1

This Caddy module is really simple (for now), it loads a local file containing a blacklist of IPs or IP ranges

```
...
134.122.168.0/24
134.122.188.0/23
137.59.236.0/22
...
```

and filter away requests coming from those IPs. 

Also, it allows to specify a comma-separated list of IPs to consider as reputable, despite the blacklist.

It works with IPV4.

It tries to do it as fast as possible, avoiding going through the list if the "fate" of the request IP has already been calculated before.

The parser of the blacklist looks in each line for a pattern that resembles an IP or an IP range, and loads it. Lines not containing any are ignored.

## Building

```bash
xcaddy build --with github.com/proofrock/caddy_smallshield
```

## Configuration

```caddyfile
{
	order caddy_smallshield first
}

:8089 {
	bind 127.0.0.1
	caddy_smallshield {
		whitelist "127.0.0.1"
		blacklist_file "/firehol_level1.netset"
	}
	respond "Hello, World!"
}
```