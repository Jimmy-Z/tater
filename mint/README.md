## mint is not a tunnel
it looks like one at a glance, but it's not.
nowadays virtually all traffic on the Internet is TLS already,
there's no point in wrapping them in TLS (or whatever) again.

handshake and a couple following packets are _encrypted_, for obfuscation.
after that, it's just plain TCP.

in an eye-balling test, it consumes about 1/3 CPU compared to stunnel under the same load.

it works for me, but no warranty.

## but it works _like_ a tunnel
tunnel as something like ssh `-D` or stunnel `protocol = socks`
* aside from the no encryption part, socks handling is on the client side,
which improves handshake latency compared to stunnel.
* aside from socks5, HTTP CONNECT is also supported.

## to do
- custom timeout in handshake
- custom timeout in socks5 handshake
- calculate padding length
