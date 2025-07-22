use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use dns::{Msg, Resolver};
use log::*;
use tokio::{net::UdpSocket, select, sync::oneshot};

use crate::fake_pool::FakePool;

pub async fn fake_dns(
	mut quit_signal: oneshot::Receiver<()>,
	listen: SocketAddr,
	pool: Rc<RefCell<FakePool>>,
) {
	let s = UdpSocket::bind(listen).await.unwrap();
	info!("listening on UDP {}", s.local_addr().unwrap());

	let mut buf = vec![0u8; 0x200];
	loop {
		select! {
			r = s.recv_from(&mut buf) => {
				match r {
					Ok((len, addr)) => {
						trace!("udp recv {} bytes from {}", len, addr);
						let Ok(mut msg) = Msg::try_from((&mut buf[..], len)) else {
							continue;
						};
						if log_enabled!(Level::Trace) {
							eprint!("{msg}");
						}
						// why can't it be coerced directly, rust?
						let len = msg.response_with(&mut *pool.borrow_mut());
						if len == 0 {
							continue;
						}
						if log_enabled!(Level::Trace) {
							let msg = Msg::try_from((&mut buf[..], len)).unwrap();
							eprint!("{msg}");
						}
						match s.send_to(&buf[..len], addr).await {
							Ok(len) => {
								trace!("udp send {} bytes to {}", len, addr);
							}
							Err(e) => {
								error!("udp send error: {}", e);
								break;
							}
						}
					}
					Err(e) => {
						error!("udp recv error: {}", e);
						break;
					}
				}
			}
			// to my surprise, &mut works
			_ = &mut quit_signal => {
				info!("exiting");
				break;
			}
		}
	}
}

impl Resolver for &mut FakePool {
	fn resolve(self, name: &[&[u8]]) -> Option<(std::net::Ipv4Addr, u32)> {
		let mut name_vec = Vec::with_capacity(0x100);
		for &l in name.iter() {
			name_vec.extend_from_slice(l);
			name_vec.push(b'.');
		}
		let name = str::from_utf8(&name_vec[..name_vec.len() - 1])
			.inspect_err(|e| debug!("invalid name: {e}"))
			.ok()?;
		debug!("resolving {name}");
		Some((self.get(name), 1))
	}
}
