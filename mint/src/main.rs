use std::{
	net::{IpAddr, SocketAddr},
	rc::Rc,
	str::FromStr,
};

use clap::{Parser, Subcommand};
use log::*;

use chacha20poly1305::{ChaCha20Poly1305 as Cipher, aead::bytes::BytesMut};
use tokio::net::{TcpListener, TcpStream, lookup_host};

use socks5::{Addr, Dst, connect, parse_dns_conf};

mod fake;
mod key;
mod proto;

use key::*;
use proto::*;

#[derive(Parser)]
#[command(version = env!("REV"))]
struct Args {
	#[command(subcommand)]
	cmd: Cmds,
}

#[derive(Subcommand)]
enum Cmds {
	#[command(alias = "s")]
	Server {
		/// PSK file path
		#[arg(short = 'k', env, default_value = "conf/psk")]
		psk: String,

		#[arg(short, env, default_value = "127.0.0.1:8080")]
		listen: String,

		/// bind address for upstream connections
		#[arg(short, env, default_value = "")]
		bind: String,

		#[arg(short, env, default_value = "")]
		dns: String,

		#[arg(short, env, default_value = "conf/fake-resp.txt")]
		fake_header: String,
	},

	#[command(alias = "c")]
	Client {
		/// PSK file path
		#[arg(short = 'k', env, default_value = "conf/psk")]
		psk: String,

		#[arg(short, env, default_value = "127.0.0.1:1080")]
		listen: String,

		#[arg(short, env, default_value = "127.0.0.1:8080")]
		server: String,

		#[arg(short, env, default_value = "conf/fake-req.txt")]
		fake_header: String,
	},

	/// generate PSK
	GenPSK,
}

#[cfg(debug_assertions)]
const LOG_LEVEL: &str = "debug";
#[cfg(not(debug_assertions))]
const LOG_LEVEL: &str = "info";

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let args = Args::parse();

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(LOG_LEVEL)).init();

	match &args.cmd {
		Cmds::Server {
			psk,
			listen,
			bind,
			dns,
			fake_header,
		} => {
			ls_run(server(psk, listen, bind, dns, fake_header)).await;
		}
		Cmds::Client {
			psk,
			listen,
			server,
			fake_header,
		} => {
			ls_run(client(psk, listen, server, fake_header)).await;
		}
		Cmds::GenPSK => {
			println!("{}", gen_psk::<Cipher>());
		}
	}
}

// runs in local set
async fn ls_run(f: impl Future) {
	let ls = tokio::task::LocalSet::new();
	ls.run_until(f).await;
}

async fn server(key: &str, listen: &str, bind: &str, dns: &str, fake_header: &str) -> Option<()> {
	let fake_header = Rc::new(fake::get_fake_header(fake_header));
	let cipher: Cipher = init_cipher(key)?;

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

	while let Ok((mut s, r_addr)) = l.accept().await {
		let _ = s.set_nodelay(true);
		let cipher = cipher.clone();
		let dns = dns.clone();
		let fake_header = fake_header.clone();
		tokio::task::spawn_local(async move {
			let mut buf = BytesMut::with_capacity(0x600);
			let Some((host, port)) =
				server_handshake(&mut s, &cipher, &mut buf, &fake_header).await
			else {
				return;
			};
			drop(buf);
			let dst = if let Ok(addr) = IpAddr::from_str(&host) {
				match addr {
					IpAddr::V4(a) => Dst {
						addr: Addr::V4(a),
						port,
					},
					IpAddr::V6(a) => Dst {
						addr: Addr::V6(a),
						port,
					},
				}
			} else {
				Dst {
					addr: Addr::DomainOwned(host),
					port,
				}
			};
			info!("{r_addr} -> {dst}");
			let Some(mut u) = connect(bind, dns, &dst).await else {
				return;
			};
			let _ = u.set_nodelay(true);
			duplex(&cipher, &mut u, &mut s).await;
			debug!("connection ended: {r_addr} -> {dst}");
		});
	}

	Some(())
}

async fn client(key: &str, listen: &str, upstream_str: &str, fake_header: &str) -> Option<()> {
	let fake_header = Rc::new(fake::get_fake_header(fake_header));
	let cipher: Cipher = init_cipher(key)?;

	let upstream: Vec<SocketAddr> = lookup_host(upstream_str)
		.await
		.inspect_err(|e| error!("failed to lookup {upstream_str}: {e}"))
		.ok()?
		.collect();
	if upstream.is_empty() {
		error!("lookup {upstream_str} yields no result");
		return None;
	}
	info!(
		"server addr: {}",
		&upstream
			.iter()
			.map(SocketAddr::to_string)
			.reduce(|a, b| a + ", " + &b)
			.unwrap()
	);
	let upstream = Rc::new(upstream);

	let l = TcpListener::bind(listen).await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

	while let Ok((mut s, r_addr)) = l.accept().await {
		let _ = s.set_nodelay(true);
		let fake_header = fake_header.clone();
		let cipher = cipher.clone();
		let upstream = upstream.clone();
		tokio::task::spawn_local(async move {
			let mut buf = BytesMut::with_capacity(0x600);
			let Some(dst) = socks5::server_handshake(&mut s).await else {
				return;
			};
			info!("{r_addr} -> {dst}");
			let Ok(mut u) = TcpStream::connect(&upstream as &[SocketAddr])
				.await
				.inspect_err(|e| error!("error connecting to upstream: {e}"))
			else {
				return;
			};
			let _ = u.set_nodelay(true);
			let Some(()) = client_handshake(
				&mut u,
				&cipher,
				&mut buf,
				&dst.addr.to_string(),
				dst.port,
				&fake_header,
			)
			.await
			else {
				return;
			};
			drop(buf);
			duplex(&cipher, &mut s, &mut u).await;
			debug!("connection ended: {r_addr} -> {dst}");
		});
	}

	Some(())
}
