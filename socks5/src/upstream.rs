// utility functions for upstream connections handling

use std::{
	net::{IpAddr, SocketAddr},
	str::FromStr,
};

use log::*;

use hickory_resolver::{
	self as resolver,
	config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig},
	net::runtime::TokioRuntimeProvider,
	proto::rr::RData,
};
use tokio::net::{TcpSocket, TcpStream, lookup_host};

use crate::{Dst, addr::Addr};

pub type Resolver = resolver::Resolver<TokioRuntimeProvider>;

pub async fn connect(
	bind: Option<IpAddr>,
	dns: Option<Resolver>,
	dst: &Dst<'_>,
) -> Option<TcpStream> {
	let addrs = match &dst.addr {
		Addr::Domain(host) => resolve(bind, dns, host, dst.port).await?,
		Addr::DomainOwned(host) => resolve(bind, dns, host, dst.port).await?,
		Addr::V4(a) => vec![SocketAddr::new(IpAddr::V4(*a), dst.port)],
		Addr::V6(a) => vec![SocketAddr::new(IpAddr::V6(*a), dst.port)],
	};
	match bind {
		None => TcpStream::connect(addrs.as_slice())
			.await
			.inspect_err(|e| {
				error!("failed to connect to \"{dst}\"{addrs:?}: {e}");
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
					error!("failed to connect to \"{dst}\"({a}): {e}");
				}) {
					return Some(s);
				}
			}
			None
		}
	}
}

async fn resolve(
	bind: Option<IpAddr>,
	dns: Option<Resolver>,
	host: &str,
	port: u16,
) -> Option<Vec<SocketAddr>> {
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
				RData::A(a) => Some(SocketAddr::new(IpAddr::V4(a.0), port)),
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
				RData::AAAA(a) => Some(SocketAddr::new(IpAddr::V6(a.0), port)),
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
	Some(addrs)
}

pub fn parse_dns_conf(dns: &str) -> Option<Resolver> {
	let mut fautly_conf = false;
	let nsc: Vec<_> = dns
		.split(',')
		.filter_map(|s| {
			// ConnectionConfig does support bind address but not interface
			// not useful
			let mut cc = ConnectionConfig::udp();
			let addr = if let Ok(a) = SocketAddr::from_str(s) {
				info!("dns server: {a}");
				cc.port = a.port();
				a.ip()
			} else if let Ok(a) = IpAddr::from_str(s) {
				info!("dns server: {a}");
				a
			} else {
				error!("invalid dns server: {s}");
				fautly_conf = true;
				return None;
			};
			Some(NameServerConfig::new(addr, true, vec![cc]))
		})
		.collect();
	if fautly_conf {
		return None;
	}
	let rc = ResolverConfig::from_parts(None, vec![], nsc);
	let mut b = Resolver::builder_with_config(rc, TokioRuntimeProvider::default());
	let ro = b.options_mut();
	ro.use_hosts_file = ResolveHosts::Never;
	ro.preserve_intermediates = false;
	ro.try_tcp_on_error = true;

	b.build()
		.inspect_err(|e| error!("error initializing resolver: {e}"))
		.ok()
}
