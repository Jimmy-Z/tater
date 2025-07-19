use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{addr::*, common::*};

// we don't support any auth
const SOCKS5_CLIENT_HELLO: &[u8] = &[SOCKS5_VER, 1, SOCKS5_NO_AUTH_REQUIRED];
const SOCKS5_CONNECT_HEAD: &[u8] = &[SOCKS5_VER, SOCKS5_CMD_CONNECT, SOCKS5_RSV];

pub async fn client_handshake<'a, T: AsyncRead + AsyncWrite + Unpin>(
	io: &mut T,
	dst: &Dst<'a>,
) -> Option<()> {
	// VER, REP, RSV
	let mut buf = [0; 3];

	io.write_all(SOCKS5_CLIENT_HELLO).await.ok()?;

	io.read_exact(&mut buf[0..2]).await.ok()?;
	expect("VER", buf[0], SOCKS5_VER)?;
	expect("AUTH", buf[1], SOCKS5_NO_AUTH_REQUIRED)?;

	io.write_all(SOCKS5_CONNECT_HEAD).await.ok()?;
	write_dst(io, dst).await?;

	io.read_exact(&mut buf[..]).await.ok()?;
	expect("VER", buf[0], SOCKS5_VER)?;
	expect("REP", buf[1], SOCKS5_REP_SUCCEED)?;
	expect("RSV", buf[2], SOCKS5_RSV)?;
	let _ = read_dst(io).await?;

	Some(())
}
