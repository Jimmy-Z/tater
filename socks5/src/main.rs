use std::{
	net::{IpAddr, SocketAddr},
	str::FromStr as _,
};

use clap::Parser;
use log::*;
use tokio::{
	io::copy_bidirectional,
	net::{TcpListener, TcpStream},
};

use socks5::{Resolver, connect, parse_dns_conf, server_handshake};

#[derive(Parser)]
#[command(version = env!("REV"))]
struct Args {
	#[clap(short, long, env, default_value = "127.0.0.1:1080")]
	pub listen: String,

	#[clap(short, long, env, default_value = "")]
	pub dns: String,

	/// bind address for upstream connections
	#[clap(short, long, env, default_value = "")]
	pub bind: String,
}

#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "info";

#[tokio::main(flavor = "current_thread")]
async fn main() {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(DEFAULT_LOG_LEVEL))
		.init();

	let args = Args::parse();
	run_local(serv(&args.listen, &args.bind, &args.dns)).await;
}

async fn serv(listen: &str, bind: &str, dns: &str) -> Option<()> {
	let bind: Option<IpAddr> = if bind.is_empty() {
		None
	} else {
		Some(
			IpAddr::from_str(bind)
				.inspect_err(|e| error!("error parsing bind address: {e}"))
				.ok()?,
		)
	};

	let dns = if dns.is_empty() {
		None
	} else {
		// if it's not empty and parse returns None
		// we should stop instead of falling back to system resolver
		Some(parse_dns_conf(dns)?)
	};

	let l = TcpListener::bind(listen)
		.await
		.inspect_err(|e| error!("error binding to {listen}: {e}"))
		.ok()?;
	info!(
		"listening on {}",
		l.local_addr()
			.inspect_err(|e| error!("error getting local address: {e}"))
			.ok()?
	);

	loop {
		let dns = dns.clone();
		let (c, addr) = l.accept().await.unwrap();
		tokio::task::spawn_local(handle(c, addr, bind, dns));
	}
}

async fn handle(mut c: TcpStream, addr: SocketAddr, bind: Option<IpAddr>, dns: Option<Resolver>) {
	let _ = c.set_nodelay(true);
	let Some(dst) = server_handshake(&mut c).await else {
		error!("server handshake on connection from {addr} failed");
		return;
	};
	info!("new connection {} -> {}", addr, &dst);
	let Some(mut u) = connect(bind, dns, &dst).await else {
		return;
	};
	let _ = u.set_nodelay(true);
	match copy_bidirectional(&mut c, &mut u).await {
		Ok((u, d)) => {
			info!("{addr} -> {dst} {u}/{d} bytes u/d");
		}
		Err(e) => {
			error!("{addr} -> {dst} pipe error: {e}");
		}
	}
}

async fn run_local(f: impl std::future::Future) {
	let l = tokio::task::LocalSet::new();
	l.run_until(f).await;
}
