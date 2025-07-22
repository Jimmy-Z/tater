Tater provides an lighter alternative to
[potato routing](https://github.com/Jimmy-Z/potato-routing/).

## two services
* fake DNS, resolves all domain names to `100.64.0.0/10`.
	* and keeps a bi-direction map between domain name and (fake) address.
* transparent proxy, forwards all received connection to an upstream SOCKS5 proxy.
	* reverse lookup the domain name then pass that to SOCKS5.

## usage
* `cargo run`
	* `cargo run -- --help`
* prepare a SOCKS5 proxy, for example, mint.
* configure dnsmasq or AdGuardHome to forward certain DNS requests to fake DNS.
* configure routing and nftables to route `100.64.0.0/10` to transparent proxy.
	* routing:
		```
		ip route add local 100.64.0.0/10 dev lo
		```
	* nftables:
		```
		chain tproxy_prerouting {
			type filter hook prerouting priority mangle
			ip daddr 100.64.0.0/10 meta l4proto tcp tproxy to 127.0.0.1:1090
		}
		```
	* note: this handles both local and forwarded traffic.

## limitations
* Linux only.
* UDP is not supported, I don't really have a motivation.

## notes
* `100.64.0.0/10` is [Carrier-grade NAT address](https://en.wikipedia.org/wiki/Carrier-grade_NAT),
normally not routable on the Internet.
