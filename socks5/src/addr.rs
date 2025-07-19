use std::{
	fmt::Display,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::*;

#[cfg_attr(test, derive(Debug, Eq))]
pub enum Addr<'a> {
	Domain(&'a str),
	DomainOwned(String),
	V4(Ipv4Addr),
	V6(Ipv6Addr),
}

#[cfg(test)]
impl<'a, 'b> PartialEq<Addr<'b>> for Addr<'a> {
	fn eq(&self, other: &Addr<'b>) -> bool {
		match (self, other) {
			(Addr::Domain(s), Addr::Domain(o)) => s == o,
			(Addr::DomainOwned(s), Addr::DomainOwned(o)) => s == o,
			(Addr::Domain(s), Addr::DomainOwned(o)) => s == o,
			(Addr::DomainOwned(s), Addr::Domain(o)) => s == o,
			(Addr::V4(s), Addr::V4(o)) => s == o,
			(Addr::V6(s), Addr::V6(o)) => s == o,
			_ => false,
		}
	}
}

impl<'a> Display for Addr<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::DomainOwned(d) => {
				write!(f, "{}", &d)
			}
			Self::Domain(d) => {
				write!(f, "{}", d)
			}
			Self::V4(a) => {
				write!(f, "{}", a)
			}
			Self::V6(a) => {
				write!(f, "{}", a)
			}
		}
	}
}

impl<'a> From<IpAddr> for Addr<'a> {
	fn from(v: IpAddr) -> Self {
		match v {
			IpAddr::V4(v4) => Addr::V4(v4),
			IpAddr::V6(v6) => Addr::V6(v6),
		}
	}
}

impl<'a> From<String> for Addr<'a> {
	fn from(v: String) -> Self {
		Self::DomainOwned(v)
	}
}

impl<'a> From<&'a str> for Addr<'a> {
	fn from(v: &'a str) -> Self {
		Self::Domain(v)
	}
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Dst<'a> {
	pub addr: Addr<'a>,
	pub port: u16,
}

impl<'a> Display for Dst<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}:{}", self.addr, self.port)
	}
}

impl<'a, T: Into<Addr<'a>>> From<(T, u16)> for Dst<'a> {
	fn from(v: (T, u16)) -> Self {
		Dst {
			addr: v.0.into(),
			port: v.1,
		}
	}
}

// can't impl Into since it's async
impl<'a> Dst<'a> {
	// unfortunately tokio doesn't want others to impl ToSockAddrs
	pub async fn lookup(&self) -> Vec<SocketAddr> {
		match &self.addr {
			Addr::Domain(d) => lookup(d, self.port).await,
			Addr::DomainOwned(d) => lookup(&d, self.port).await,
			Addr::V4(a) => vec![SocketAddr::new(IpAddr::V4(*a), self.port)],
			Addr::V6(a) => vec![SocketAddr::new(IpAddr::V6(*a), self.port)],
		}
	}
}

async fn lookup(d: &str, port: u16) -> Vec<SocketAddr> {
	match tokio::net::lookup_host((d, port)).await {
		Ok(iter) => iter.collect(),
		Err(e) => {
			error!("error trying to lookup {}: {}", d, e);
			Vec::new()
		}
	}
}

pub async fn read_dst<'a, T: AsyncRead + Unpin>(r: &mut T) -> Option<Dst<'a>> {
	let mut buf = [0u8; 0x100];

	let atyp = r
		.read_u8()
		.await
		.inspect_err(|e| error!("failed to read ATYP: {}", e))
		.ok()?;
	let addr: Addr = match atyp {
		SOCKS5_ATYP_DOMAINNAME => {
			let addr_len = r
				.read_u8()
				.await
				.inspect_err(|e| error!("failed to read DST.ADDR: {}", e))
				.ok()?;
			r.read_exact(&mut buf[..(addr_len as usize)])
				.await
				.inspect_err(|e| error!("failed to read DST.ADDR(DOMAINNAME): {}", e))
				.ok()?;
			Addr::DomainOwned(
				std::str::from_utf8(&buf[..(addr_len as usize)])
					.inspect_err(|e| error!("invalid DST.ADDR(DOMAINNAME): {}", e))
					.ok()?
					.to_string(),
			)
		}
		SOCKS5_ATYP_V4 => {
			r.read_exact(&mut buf[..4])
				.await
				.inspect_err(|e| error!("failed to read DST.ADDR(IPV4): {}", e))
				.ok()?;
			Addr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&buf[..4]).unwrap()))
		}
		SOCKS5_ATYP_V6 => {
			r.read_exact(&mut buf[..16])
				.await
				.inspect_err(|e| error!("failed to read DST.ADDR(IPV6): {}", e))
				.ok()?;
			Addr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap()))
		}
		_ => {
			error!("invalid ATYP {}", atyp);
			return None;
		}
	};
	let port: u16 = r
		.read_u16()
		.await
		.inspect_err(|e| error!("failed to read DST.PORT: {}", e))
		.ok()?;
	Some(Dst { addr, port })
}

pub async fn write_dst<'a, T: AsyncWrite + Unpin>(w: &mut T, dst: &Dst<'a>) -> Option<()> {
	match &dst.addr {
		Addr::Domain(d) => write_domain(w, d).await?,
		Addr::DomainOwned(d) => write_domain(w, d).await?,
		Addr::V4(addr) => {
			w.write_u8(SOCKS5_ATYP_V4)
				.await
				.inspect_err(|e| error!("failed to write ATYP: {}", e))
				.ok()?;
			w.write_all(&addr.octets())
				.await
				.inspect_err(|e| error!("failed to write DST.ADDR(IPV4): {}", e))
				.ok()?;
		}
		Addr::V6(addr) => {
			w.write_u8(SOCKS5_ATYP_V6)
				.await
				.inspect_err(|e| error!("failed to write ATYP: {}", e))
				.ok()?;
			w.write_all(&addr.octets())
				.await
				.inspect_err(|e| error!("failed to write DST.ADDR(IPV6): {}", e))
				.ok()?;
		}
	}
	w.write_u16(dst.port)
		.await
		.inspect_err(|e| error!("failed to write DST.PORT: {}", e))
		.ok()
}

pub async fn write_domain<T: AsyncWrite + Unpin>(w: &mut T, d: &str) -> Option<()> {
	w.write_u8(SOCKS5_ATYP_DOMAINNAME)
		.await
		.inspect_err(|e| error!("failed to write ATYP: {}", e))
		.ok()?;
	let bytes = d.as_bytes();
	if bytes.len() >= 0x100 {
		error!(
			"host too long({} > {}), this is not supported",
			bytes.len(),
			0xff
		);
		return None;
	}
	w.write_u8(bytes.len() as u8)
		.await
		.inspect_err(|e| error!("failed to write DST.ADDR len: {}", e))
		.ok()?;
	w.write_all(bytes)
		.await
		.inspect_err(|e| error!("failed to write DST.ADDR(DOMAINNAME): {}", e))
		.ok()
}

#[cfg(test)]
mod tests {
	use rand::{Rng, distr::Alphanumeric, rng, rngs::ThreadRng};

	use super::*;

	async fn test_addr<'a, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
		addr: Addr<'a>,
		r: &mut R,
		w: &mut W,
		rand: &mut ThreadRng,
	) {
		let port: u16 = rand.random();
		let dst = Dst { addr, port };
		let (_, r) = tokio::join!(write_dst(w, &dst), read_dst(r));
		let r = r.unwrap();
		assert_eq!(dst, r);
	}

	#[tokio::test]
	async fn test_addr_handling() {
		let (mut r, mut w) = tokio::io::simplex(0x100);
		let mut rand = rng();

		for _ in 0..0x1000 {
			let alen: u8 = rand.random();
			let addr: String = (&mut rand)
				.sample_iter(&Alphanumeric)
				.take(alen as usize)
				.map(char::from)
				.collect();
			let addr = Addr::DomainOwned(addr);
			test_addr(addr, &mut r, &mut w, &mut rand).await;
		}

		for _ in 0..0x1000 {
			let addr: [u8; 4] = rand.random();
			let addr = Addr::V4(Ipv4Addr::from(addr));
			test_addr(addr, &mut r, &mut w, &mut rand).await;
		}
		for _ in 0..0x1000 {
			let addr: [u8; 16] = rand.random();
			let addr = Addr::V6(Ipv6Addr::from(addr));
			test_addr(addr, &mut r, &mut w, &mut rand).await;
		}
	}
}
