use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use dns::{Msg, Resolver};
use log::*;
use tokio::{io::Result, net::UdpSocket, select, sync::oneshot};

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
			r = s.recv_from(&mut buf) => handle_req(&s, &mut buf[..], &pool, r).await,
			// to my surprise, &mut works
			_ = &mut quit_signal => {
				info!("exiting");
				break;
			}
		}
	}
}

async fn handle_req(
	s: &UdpSocket,
	buf: &mut [u8],
	pool: &Rc<RefCell<FakePool>>,
	r: Result<(usize, SocketAddr)>,
) {
	let Ok((len, addr)) = r.inspect_err(|e| error!("udp recv error: {e}")) else {
		return;
	};
	trace!("udp recv {len} bytes from {addr}");
	let Ok(mut msg) = Msg::try_from((&mut buf[..], len)) else {
		return;
	};
	if log_enabled!(Level::Trace) {
		eprint!("{msg}");
	}
	// why can't it be coerced directly, rust?
	let len = msg.response_with(&mut *pool.borrow_mut());
	if len == 0 {
		return;
	}
	if log_enabled!(Level::Trace) {
		let msg = Msg::try_from((&mut buf[..], len)).unwrap();
		eprint!("{msg}");
	}
	match s.send_to(&buf[..len], addr).await {
		Ok(len) => {
			trace!("udp send {len} bytes to {addr}");
		}
		Err(e) => {
			error!("udp send error: {e}");
		}
	}
}

impl Resolver for &mut FakePool {
	fn resolve(self, name: &str) -> Option<(std::net::Ipv4Addr, u32)> {
		Some((self.get(name), 1))
	}
}
