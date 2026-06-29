use std::{
	net::{IpAddr, SocketAddr},
	rc::Rc,
	str::FromStr,
};

use clap::{Parser, Subcommand};
use log::*;

use chacha20poly1305::{ChaCha20Poly1305 as Cipher, aead::bytes::BytesMut};
use hickory_resolver as resolver;
use tokio::net::{TcpListener, TcpSocket, TcpStream, lookup_host};

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
		IpAddr::from_str(bind)
			.inspect_err(|e| error!("error parsing bind address: {e}"))
			.ok()
	};

	let dns = parse_dns(dns);

	let l = TcpListener::bind(listen).await.unwrap();
	info!("listening on {}", l.local_addr().unwrap());

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
			info!("{r_addr} -> {host}:{port}");
			let Some(mut u) = connect(bind, dns, &host, port).await else {
				return;
			};
			let _ = u.set_nodelay(true);
			duplex(&cipher, &mut u, &mut s).await;
			debug!("connection ended: {r_addr} -> {host}:{port}");
		});
	}

	Some(())
}

async fn connect(
	bind: Option<IpAddr>,
	dns: Option<Resolver>,
	host: &str,
	port: u16,
) -> Option<TcpStream> {
	let addrs: Vec<SocketAddr> = match (dns, bind) {
		(None, None) => lookup_host(format!("{host}:{port}"))
			.await
			.inspect_err(|e| {
				error!("failed to resolve \"{host}\": {e}");
			})
			.ok()?
			.collect(),
		(None, Some(IpAddr::V4(_))) => lookup_host(format!("{host}:{port}"))
			.await
			.inspect_err(|e| {
				error!("failed to resolve \"{host}\": {e}");
			})
			.ok()?
			.filter(SocketAddr::is_ipv4)
			.collect(),
		(None, Some(IpAddr::V6(_))) => lookup_host(format!("{host}:{port}"))
			.await
			.inspect_err(|e| {
				error!("failed to resolve \"{host}\": {e}");
			})
			.ok()?
			.filter(SocketAddr::is_ipv4)
			.collect(),
		(Some(dns), None) => dns
			.lookup_ip(host)
			.await
			.inspect_err(|e| {
				error!("failed to resolve \"{host}\": {e}");
			})
			.ok()?
			.iter()
			.map(|i| SocketAddr::new(i, port))
			.collect(),
		(Some(dns), Some(IpAddr::V4(_))) => dns
			.ipv4_lookup(host)
			.await
			.inspect_err(|e| {
				error!("failed to resolve \"{host}\": {e}");
			})
			.ok()?
			.answers()
			.iter()
			.filter_map(|r| match r.data {
				resolver::proto::rr::RData::A(a) => Some(SocketAddr::new(IpAddr::V4(a.0), port)),
				_ => None,
			})
			.collect(),
		(Some(dns), Some(IpAddr::V6(_))) => dns
			.ipv6_lookup(host)
			.await
			.inspect_err(|e| {
				error!("failed to resolve \"{host}\": {e}");
			})
			.ok()?
			.answers()
			.iter()
			.filter_map(|r| match r.data {
				resolver::proto::rr::RData::AAAA(a) => Some(SocketAddr::new(IpAddr::V6(a.0), port)),
				_ => None,
			})
			.collect(),
	};
	if addrs.is_empty() {
		error!("failed to resolve \"{host}\", no addresses");
		return None;
	} else {
		debug!("resolved: {addrs:?}");
	}
	match bind {
		None => TcpStream::connect(addrs.as_slice())
			.await
			.inspect_err(|e| {
				error!("failed to connect to \"{host}\"{addrs:?}: {e}");
			})
			.ok(),
		Some(bind) => {
			for a in addrs {
				let s = match bind {
					IpAddr::V4(_) => TcpSocket::new_v4(),
					IpAddr::V6(_) => TcpSocket::new_v6(),
				}
				.inspect_err(|e| {
					error!("failed to create socket: {e}");
				})
				.ok()?;
				// reuse addr?
				s.bind(SocketAddr::new(bind, 0))
					.inspect_err(|e| {
						error!("failed to bind to {bind}: {e}");
					})
					.ok()?;
				if let Ok(s) = s.connect(a).await.inspect_err(|e| {
					error!("failed to connect to \"{host}\"({a}): {e}");
				}) {
					return Some(s);
				}
			}
			None
		}
	}
}

type Resolver = resolver::Resolver<resolver::net::runtime::TokioRuntimeProvider>;

fn parse_dns(dns: &str) -> Option<Resolver> {
	if dns.is_empty() {
		return None;
	};
	let nsc: Vec<_> = dns
		.split(',')
		.map(|s| {
			let mut cc = resolver::config::ConnectionConfig::udp();
			let addr = if let Ok(a) = SocketAddr::from_str(s) {
				info!("dns server: {a}");
				cc.port = a.port();
				a.ip()
			} else if let Ok(a) = IpAddr::from_str(s) {
				info!("dns server: {a}");
				a
			} else {
				panic!("invalid dns server: {s}");
			};
			resolver::config::NameServerConfig::new(addr, true, vec![cc])
		})
		.collect();
	let rc = resolver::config::ResolverConfig::from_parts(None, vec![], nsc);
	let mut b = resolver::Resolver::builder_with_config(
		rc,
		resolver::net::runtime::TokioRuntimeProvider::default(),
	);
	let ro = b.options_mut();
	ro.use_hosts_file = resolver::config::ResolveHosts::Never;
	ro.preserve_intermediates = false;
	ro.try_tcp_on_error = true;

	b.build()
		.inspect_err(|e| error!("error initializing resolver: {e}"))
		.ok()
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
