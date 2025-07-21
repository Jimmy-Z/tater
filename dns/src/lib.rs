use std::{fmt::Display, net::Ipv4Addr};

use log::*;

mod constants;

use constants::*;

type Resolver = fn(&[&[u8]]) -> Option<(Ipv4Addr, u32)>;

// barebones dns library for fakedns
// it does 2 things only:
// 	parse query
// 	write response (in-place), with 1 A record

pub struct Msg<'a> {
	msg: &'a mut [u8],
	len: usize,
}

impl<'a> Msg<'a> {
	// write response in-place
	pub fn response_with(&mut self, resolver: Resolver) -> usize {
		// check headers
		if self.opcode() != OPCODE_QUERY {
			self.set_response();
			self.set_rcode(RCODE_NOTIMP);
			return self.len;
		}
		if self.qd_count() < 1 {
			self.set_response();
			self.set_rcode(RCODE_FORMERR);
			return self.len;
		}

		let mut name = Vec::with_capacity(8);
		let mut offset = DNS_HEADER_LEN;
		// parse name
		loop {
			if offset + 1 > self.len {
				return 0;
			}
			let label_len = self.msg[offset] as usize;
			if label_len == 0 {
				offset += 1;
				break;
			}
			if offset + 1 + label_len > self.len {
				return 0;
			}
			name.push(&self.msg[offset + 1..offset + 1 + label_len]);
			offset += 1 + label_len;
		}
		// QTYPE QCLASS
		if offset + 4 > self.len {
			return 0;
		}
		let qtype = u16be(&self.msg[offset..offset + 2]);
		let qclass = u16be(&self.msg[offset + 2..offset + 4]);
		offset += 4;
		println!(
			"{} {} {}",
			name.iter()
				.map(|b| str::from_utf8(b).unwrap())
				.collect::<Vec<_>>()
				.join("."),
			type2str(qtype),
			class2str(qclass)
		);
		if qtype != TYPE_A || qclass != CLASS_IN {
			self.set_response();
			self.set_rcode(RCODE_NOTIMP);
			return self.len;
		}
		let Some((addr, ttl)) = resolver(&name) else {
			// rfc says we shouldn't set Name Error since we're not authoritative
			self.set_response();
			if self.rd() {
				self.set_ra();
			}
			return self.len;
		};
		// start writting response
		self.set_response_header(RCODE_NOERROR, 1, 1, 0, 0);
		// to do: check available buffer, shouldn't be a problem though
		// rfc1034 4.1.4 message compression
		// qname is conveniently always just after the header
		let name: u16 = 0b1100_0000_0000_0000 | DNS_HEADER_LEN as u16;
		self.msg[offset..offset + 2].copy_from_slice(&name.to_be_bytes());
		self.msg[offset + 2..offset + 4].copy_from_slice(&TYPE_A.to_be_bytes());
		self.msg[offset + 4..offset + 6].copy_from_slice(&CLASS_IN.to_be_bytes());
		self.msg[offset + 6..offset + 10].copy_from_slice(&ttl.to_be_bytes());
		self.msg[offset + 10..offset + 12].copy_from_slice(&4u16.to_be_bytes());
		self.msg[offset + 12..offset + 16].copy_from_slice(&addr.octets());
		offset += 16;

		// length of the response
		offset
	}

	fn set_response_header(&mut self, rcode: u8, qd: u16, an: u16, ns: u16, ar: u16) {
		self.set_response();
		if self.rd() {
			self.set_ra();
		}
		self.set_rcode(rcode);
		self.msg[4..6].copy_from_slice(&qd.to_be_bytes());
		self.msg[6..8].copy_from_slice(&an.to_be_bytes());
		self.msg[8..10].copy_from_slice(&ns.to_be_bytes());
		self.msg[10..12].copy_from_slice(&ar.to_be_bytes());
	}

	fn id(&self) -> u16 {
		u16be(&self.msg[0..2])
	}
	fn qd_count(&self) -> u16 {
		u16be(&self.msg[4..6])
	}
	fn an_count(&self) -> u16 {
		u16be(&self.msg[6..8])
	}
	fn ns_count(&self) -> u16 {
		u16be(&self.msg[8..10])
	}
	fn ar_count(&self) -> u16 {
		u16be(&self.msg[10..12])
	}

	fn get_flag(&self, o_byte: u8, o_bit: u8) -> bool {
		get_bit(self.msg[o_byte as usize], o_bit)
	}

	fn tc(&self) -> bool {
		self.get_flag(2, 1)
	}
	fn rd(&self) -> bool {
		self.get_flag(2, 0)
	}
	fn z(&self) -> bool {
		self.get_flag(3, 6)
	}

	fn opcode(&self) -> u8 {
		get_bits(self.msg[2], 3, 4)
	}
	fn rcode(&self) -> u8 {
		get_bits(self.msg[3], 0, 4)
	}

	fn set_response(&mut self) {
		set_bit(&mut self.msg[2], 7)
	}
	fn set_ra(&mut self) {
		set_bit(&mut self.msg[3], 7)
	}
	fn set_rcode(&mut self, c: u8) {
		set_bits(&mut self.msg[3], 0, 4, c);
	}
}

#[derive(Debug)]
pub enum ParseError {
	Invalid,
	Truncated,
}

impl<'a> TryFrom<(&'a mut [u8], usize)> for Msg<'a> {
	type Error = ParseError;
	fn try_from(msg: (&'a mut [u8], usize)) -> Result<Self, Self::Error> {
		let (msg, len) = msg;
		if len < DNS_HEADER_LEN {
			debug!("too short to contain a dns mesasge: {len}");
			return Err(ParseError::Invalid);
		}
		// eprintln!("{:08b} {:08b}", msg[2], msg[3]);
		let msg = Msg { msg, len };
		if msg.tc() {
			return Err(ParseError::Truncated);
		}
		if msg.z() {
			eprintln!("header: reserved bit is not zero");
		}
		Ok(msg)
	}
}

// mimics dig/drill output
impl<'a> Display for Msg<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(
			f,
			";; ->>HEADER<<- opcode: {}, rcode: {}, id: {}",
			opcode2str(self.opcode()),
			rcode2str(self.rcode()),
			self.id()
		)?;
		write!(f, ";; flags:")?;
		for &(o0, o1, name) in FLAGS {
			if self.get_flag(o0, o1) {
				write!(f, " {name}")?;
			}
		}
		writeln!(
			f,
			"; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
			self.qd_count(),
			self.an_count(),
			self.ns_count(),
			self.ar_count()
		)
	}
}

fn u16be(bytes: &[u8]) -> u16 {
	u16::from_be_bytes(bytes.try_into().unwrap())
}

// I really liked bitfields in C
fn get_bit(b: u8, o: u8) -> bool {
	(b >> o) & 1 == 1
}
fn get_bits(b: u8, o: u8, l: u8) -> u8 {
	(b >> o) & ((1 << l) - 1)
}
fn set_bit(b: &mut u8, o: u8) {
	*b |= 1 << o;
}
fn set_bits(b: &mut u8, o: u8, l: u8, v: u8) {
	*b = (*b & !(((1 << l) - 1) << o)) | (v << o);
}

#[cfg(test)]
mod tests {}
