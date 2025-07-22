// be aware TPROXY is not REDIRECT
//	https://www.kernel.org/doc/Documentation/networking/tproxy.txt
// short version:
//	- REDIRECT use a regular listening socket
//		then use getsockopt(SO_ORIGINAL_DST) to get the original dest addr
//	- TPROXY needs a listening socket with setsockopt(IP_TRANSPARENT)
//		no special handling is required to get dest addr
//		also the binary requires CAP_NET_ADMIN
//			`setcap cap_net_admin=ep target/debug/tater`

use std::{
	cell::RefCell,
	net::{IpAddr, SocketAddr},
	rc::Rc,
};

use log::*;
use socket2::Socket;
use tokio::{
	io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
	net::{TcpListener, TcpStream},
	select,
	sync::oneshot,
	task,
};

use crate::fake_pool::FakePool;

pub async fn tproxy(
	mut quit_signal: oneshot::Receiver<()>,
	bind_addr: SocketAddr,
	pool: Rc<RefCell<FakePool>>,
	socks_addr: SocketAddr,
) -> Option<()> {
	// note: I tried creating the socket using socket2, but it didn't work
	//	accept() always returns os error 22
	let s = TcpListener::bind(bind_addr).await.unwrap();
	// convert to socket2 to set IP_TRANSPARENT
	let s = Socket::from(s.into_std().unwrap());
	s.set_ip_transparent_v4(true).unwrap();
	// convert back to tokio
	let s = TcpListener::from_std(s.into()).unwrap();
	info!("listening on TCP {}", s.local_addr().unwrap());

	loop {
		select! {
			r = s.accept() => {
				match r {
					Ok((stream, addr)) => {
						let dest_addr = stream.local_addr().unwrap();
						info!("tcp {addr} -> {dest_addr}");
						let dest_ip4 = match dest_addr.ip() {
							IpAddr::V4(v) => v,
							_ => {
								error!("\tonly supports IPv4");
								continue;
							}
						};
						let name = match pool.borrow_mut().get_reverse(dest_ip4) {
							Some(v) => v,
							_ => {
								error!("\tfake pool doesn't have the entry {dest_ip4}");
								continue;
							}
						};
						info!("\t{}", &name);
						task::spawn_local(proxy(stream, name, dest_addr.port(), socks_addr));
					}
					Err(e) => {
						error!("tcp accept error: {e}");
						break;
					}
				}
			}
			_ = &mut quit_signal => {
				info!("exiting");
				break;
			}
		}
	}

	Some(())
}

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_RSV: u8 = 0x00;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAINNAME: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

const SOCKS5_CLIENT_HELLO: &[u8] = &[SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE];
const SOCKS5_CONNECT_HEAD: &[u8] = &[
	SOCKS5_VERSION,
	SOCKS5_CMD_CONNECT,
	SOCKS5_RSV,
	SOCKS5_ATYP_DOMAINNAME,
];

async fn proxy(
	mut stream: TcpStream,
	dest_name: String,
	dest_port: u16,
	socks_addr: SocketAddr,
) -> Option<()> {
	let mut socks = TcpStream::connect(socks_addr).await.unwrap();
	socks.set_nodelay(true).unwrap();

	let mut buf = vec![0u8; 0x110];

	socks.write_all(SOCKS5_CLIENT_HELLO).await.ok()?;
	socks.read_exact(&mut buf[..2]).await.ok()?;
	if buf[0] != SOCKS5_VERSION {
		error!("socks5 version mismatch: {}", buf[0]);
		return None;
	};
	if buf[1] != SOCKS5_AUTH_NONE {
		error!("socks5 auth method not supported: {}", buf[1]);
		return None;
	};
	// assemble/write the connect command
	buf[..SOCKS5_CONNECT_HEAD.len()].copy_from_slice(SOCKS5_CONNECT_HEAD);
	let dest_bytes = dest_name.as_bytes();
	buf[SOCKS5_CONNECT_HEAD.len()] = dest_bytes.len() as u8;
	buf[SOCKS5_CONNECT_HEAD.len() + 1..SOCKS5_CONNECT_HEAD.len() + 1 + dest_bytes.len()]
		.copy_from_slice(dest_bytes);
	buf[SOCKS5_CONNECT_HEAD.len() + 1 + dest_bytes.len()
		..SOCKS5_CONNECT_HEAD.len() + 1 + dest_bytes.len() + 2]
		.copy_from_slice(&dest_port.to_be_bytes());
	socks
		.write_all(&buf[..SOCKS5_CONNECT_HEAD.len() + 1 + dest_bytes.len() + 2])
		.await
		.ok()?;

	// read the response
	socks.read_exact(&mut buf[..4]).await.ok()?;
	if buf[0] != SOCKS5_VERSION {
		error!("socks5 version mismatch: {}", buf[0]);
		return None;
	};
	if buf[1] != 0x00 {
		error!("socks5 connect failed: {}", buf[1]);
		return None;
	};
	if buf[2] != SOCKS5_RSV {
		error!("socks5 reserved field mismatch: {}", buf[2]);
		return None;
	};
	match buf[3] {
		SOCKS5_ATYP_IPV4 => {
			socks.read_exact(&mut buf[..4]).await.ok()?;
		}
		SOCKS5_ATYP_IPV6 => {
			socks.read_exact(&mut buf[..16]).await.ok()?;
		}
		SOCKS5_ATYP_DOMAINNAME => {
			socks.read_exact(&mut buf[..1]).await.ok()?;
			let n_len = buf[0] as usize;
			socks.read_exact(&mut buf[..n_len]).await.ok()?;
		}
		_ => {
			error!("socks5 address type not supported: {}", buf[4]);
			return None;
		}
	};
	socks.read_exact(&mut buf[..2]).await.ok()?;

	drop(buf);

	copy_bidirectional(&mut socks, &mut stream).await.ok()?;

	Some(())
}
