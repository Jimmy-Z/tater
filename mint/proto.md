
* general
	* it's kinda like SOCKS5.
	* but handshake is encrypted.
	* handshake message (including padding) should not exceed MTU
		* so it should always arrive in one packet.
	* message MUST be written in a single write call.
* message format
	* a fake header, ends with double CRLF
		* for reasons
	* nonce
	* encrypted payload
		* request or response
		* padding
* request:
	* 1 byte VER, 0
	* 1 byte length of the host
	* host
	* 2 bytes dest port
* response:
	* 1 byte reply, 0 means succeed
