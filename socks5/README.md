just enough SOCKS5 implementation, tokio based.

## limitations
* only tcp connect
* it's intended for LAN usage so not even user/pass auth support.
* not RFC compliant
	* we don't support GSSAPI, which is MUST in RFC 1928.3
	* server replies SUCCEEDED **immediately**,
	before connection to dst actually establishes.
		* subsequent connection to dst might still fail,
		despite been responsed with SUCCEEDED.
		* we never return errors like "X'04' Host unreachable" or "X'05' Connection refused".
	* but should be RFC _compatible_.
		* server was tested by curl/firefox/chrome.
			* `curl --socks5-hostname 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace`
		* client was tested only against this server though.

## more
* the server additionally supports HTTP CONNECT, on the same port.
	* simply speaking, `curl --proxy 127.0.0.1:1080` (should) work basically the same.
	* all other HTTP methods are simply rejected.
		* so it's a _HTTPS_ only http proxy.

## about the not-so-complaint response behavior
this is mainly for mint client,
in which socks5 serves as the UA facing protocol.
in this scenario, the non-complaint response behavior is actually beneficial:
it reduces connect RTT, since from the point of view of UA,
the connection is establised in RTT<sub>(1)</sub> of UA - mint client,
instead of RTT<sub>(2)</sub> of UA - mint client - mint server - dst.
since mint client is usually deployed in localhost or in LAN,
RTT<sub>(1)</sub> is usually dramatically lower than RTT<sub>(2)</sub>,
like <1ms vs >150ms.

the downside, however, is that clients might report unexpected error,
keep that in mind.
