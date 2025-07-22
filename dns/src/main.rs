use std::net::{Ipv4Addr, UdpSocket};

use dns::{Msg, Resolver};

fn main() -> std::io::Result<()> {
	let d = UdpSocket::bind("127.0.0.1:1053")?;

	let mut buf = [0; 0x200];
	loop {
		let (len, addr) = d.recv_from(&mut buf)?;
		println!("{len} bytes from {addr}");
		if let Ok(mut msg) = Msg::try_from((&mut buf[..], len)) {
			println!("{msg}");
			let len = msg.response_with(Dummy());
			if len > 0 {
				println!("{len} bytes to {addr}");
				let msg = Msg::try_from((&mut buf[..], len)).unwrap();
				println!("{msg}");
				d.send_to(&buf[..len], addr)?;
			}
		}
	}
}

struct Dummy();

impl Resolver for Dummy {
	fn resolve(self, _name: &[&[u8]]) -> Option<(Ipv4Addr, u32)> {
		Some((Ipv4Addr::new(127, 25, 0, 1), 42))
	}
}
