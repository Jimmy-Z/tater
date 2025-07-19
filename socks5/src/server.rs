use bytes::BytesMut;
use log::*;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{addr::*, common::*};

// VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
const REP_LEN: usize = 4 + 4 + 2;

pub async fn server_handshake<'a, T: AsyncRead + AsyncWrite + Unpin>(
	io: &mut T,
) -> Option<Dst<'a>> {
	let mut buf = [0u8; REP_LEN];

	// VER NMETHODS
	io.read_exact(&mut buf[0..2])
		.await
		.inspect_err(|e| error!("failed to read client hello: {e}"))
		.ok()?;

	// HTTP CONNECT support
	if eq_ignore_ascii_case(&buf[0..2], "CO") {
		return connect_handshake(io).await;
	}
	expect("VER", buf[0], SOCKS5_VER)?;
	// ignored
	let nmethods = buf[1] as usize;
	for _ in 0..nmethods {
		_ = io
			.read_u8()
			.await
			.inspect_err(|e| error!("failed to read client auth methods: {e}"));
	}

	buf[0] = SOCKS5_VER;
	buf[1] = SOCKS5_NO_AUTH_REQUIRED;
	io.write_all(&buf[..2])
		.await
		.inspect_err(|e| error!("failed to write auth method choice: {e}"))
		.ok()?;

	// VER CMD RSV
	io.read_exact(&mut buf[0..3])
		.await
		.inspect_err(|e| error!("failed to read client request: {e}"))
		.ok()?;
	expect("VER", buf[0], SOCKS5_VER)?;
	expect("RSV", buf[2], SOCKS5_RSV)?;
	if expect("CMD", buf[1], SOCKS5_CMD_CONNECT).is_none() {
		reply(&mut buf, io, SOCKS5_REP_CMD_NOT_SUPPORTED)
			.await
			.ok()?;
		return None;
	}
	let dst = read_dst(io).await?;
	debug!("SOCKS5 {}", &dst);

	reply(&mut buf, io, SOCKS5_REP_SUCCEED).await.ok()?;

	Some(dst)
}

async fn reply<T: AsyncRead + AsyncWrite + Unpin>(
	buf: &mut [u8],
	io: &mut T,
	rep: u8,
) -> io::Result<()> {
	buf[0] = SOCKS5_VER;
	buf[1] = rep;
	buf[2] = SOCKS5_RSV;
	buf[3] = SOCKS5_ATYP_V4;
	io.write_all(&buf[..REP_LEN])
		.await
		.inspect_err(|e| error!("error writting REP: {e}"))
}

const EOH: &[u8] = b"\r\n\r\n";
const RES_OK: &[u8] = b"HTTP/1.1 200 :)\r\n\r\n";

// handles HTTP connect, again this is a just enough implementation
pub async fn connect_handshake<'a, T: AsyncRead + AsyncWrite + Unpin>(
	io: &mut T,
) -> Option<Dst<'a>> {
	let mut buf = BytesMut::with_capacity(0x100);
	// caution: naive assumption that the client request was sent in one go
	io.read_buf(&mut buf).await.ok()?;

	if buf.len() < EOH.len() {
		error!("request to short to even contain end of header");
		return None;
	}

	if &buf[buf.len() - 4..] != EOH {
		error!("end of header not found");
		return None;
	}

	let req = str::from_utf8(&buf)
		.inspect_err(|e| error!("error converting req to string: {e}"))
		.ok()?;

	// get 1st line, headers are ignored
	let req = req.split("\r\n").next().unwrap();

	// CONNECT <host>:<port> HTTP/1.1
	let req: [&str; 3] = req
		.split(' ')
		.collect::<Vec<_>>()
		.try_into()
		.inspect_err(|_| error!("error parsing request line: {req}"))
		.ok()?;

	// "CO" ate in socks5_handshake for protocol identification
	if !req[0].eq_ignore_ascii_case("NNECT") {
		error!("invalid method, expecting CONNECT, got CO{}", req[0]);
		return None;
	}

	let dest: [&str; 2] = req[1]
		.split(':')
		.collect::<Vec<_>>()
		.try_into()
		.inspect_err(|_| error!("error parsing destination: {}", req[1]))
		.ok()?;

	let port: u16 = dest[1]
		.parse()
		.inspect_err(|e| error!("error parsing port {}: {}", dest[1], e))
		.ok()?;

	let dst = Dst::from((String::from(dest[0]), port));
	debug!("CO{} {} {}", req[0], &dst, req[2]);

	io.write_all(RES_OK)
		.await
		.inspect_err(|e| error!("error writing response to client: {e}"))
		.ok()?;

	Some(dst)
}

fn eq_ignore_ascii_case(a: &[u8], b: &str) -> bool {
	let Ok(a) = str::from_utf8(a) else {
		return false;
	};
	a.eq_ignore_ascii_case(b)
}
