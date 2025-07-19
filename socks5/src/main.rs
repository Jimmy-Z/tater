use std::net::SocketAddr;

use log::*;
use tokio::{
	io::copy_bidirectional,
	net::{TcpListener, TcpStream, ToSocketAddrs},
};

use socks5::server_handshake;

#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "info";

#[tokio::main(flavor = "current_thread")]
async fn main() {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(DEFAULT_LOG_LEVEL))
		.init();

	let args: Vec<String> = std::env::args().collect();
	if args.len() == 1 {
		run_local(serv("127.0.0.1:1080")).await;
	} else {
		run_local(serv(&args[1])).await;
	}
}

async fn serv<T: ToSocketAddrs>(addr: T) {
	let l = TcpListener::bind(addr).await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

	loop {
		let (c, addr) = l.accept().await.unwrap();
		tokio::task::spawn_local(handle(c, addr));
	}
}

async fn handle(mut c: TcpStream, addr: SocketAddr) {
	let _ = c.set_nodelay(true);
	let Some(dst) = server_handshake(&mut c).await else {
		error!("server handshake on connection from {} failed", addr);
		return;
	};
	info!("new connection {} -> {}", addr, &dst);
	let dst_lu = dst.lookup().await;
	if dst_lu.len() == 0 {
		error!("lookup failed for {}", dst);
		return;
	}
	let Ok(mut u) = TcpStream::connect(&dst_lu[..]).await.inspect_err(|e| {
		error!("connect to {} failed: {}", dst, e);
	}) else {
		return;
	};
	let _ = u.set_nodelay(true);
	match copy_bidirectional(&mut c, &mut u).await {
		Ok((u, d)) => {
			info!("{} -> {} {}/{} bytes u/d", addr, dst, u, d);
		}
		Err(e) => {
			error!("{} -> {} pipe error: {}", addr, dst, e);
		}
	}
}

async fn run_local(f: impl std::future::Future) {
	let l = tokio::task::LocalSet::new();
	l.run_until(f).await;
}
