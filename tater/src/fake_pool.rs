use std::{
	cell::RefCell,
	collections::HashMap,
	net::Ipv4Addr,
	rc::Rc,
	time::{Duration, Instant},
};

use log::*;
use tokio::{select, sync::oneshot, time::sleep};

struct Entry {
	pub name: Rc<str>,
	pub last_access: Instant,
}

pub struct FakePool {
	base: u32,
	mask: u32,
	current: u32,
	entries: HashMap<Rc<str>, u32>,
	reverse: HashMap<u32, Entry>,
}

impl FakePool {
	pub fn new(base: Ipv4Addr, cidr_len: u8, init_cap: usize) -> FakePool {
		FakePool {
			base: ip4_to_u32(base),
			mask: (1 << (32 - cidr_len as u32)) - 1,
			current: 0,
			entries: HashMap::with_capacity(init_cap),
			reverse: HashMap::with_capacity(init_cap),
		}
	}

	pub fn get(&mut self, name: &str) -> Ipv4Addr {
		let n = match self.entries.get(name) {
			// note: last_access is not updated here
			Some(v) => *v,
			_ => {
				let n = self.current;
				loop {
					self.current = (self.current + 1) & self.mask;
					// no infinite loop, but it may overwrite existing entry
					// but unlikely since the pool should be large enough
					if !self.reverse.contains_key(&self.current) || self.current == n {
						break;
					}
				}

				let name: Rc<str> = Rc::from(name);
				self.entries.insert(name.clone(), n);
				self.reverse.insert(
					n,
					Entry {
						name: name.clone(),
						last_access: Instant::now(),
					},
				);
				n
			}
		};
		let a = u32_to_ip4(self.base + n);
		info!("{name} -> {a}");
		a
	}

	pub fn get_reverse(&mut self, addr: Ipv4Addr) -> Option<String> {
		let entry = self.reverse.get_mut(&(ip4_to_u32(addr) - self.base))?;
		entry.last_access = Instant::now();
		Some((&entry.name as &str).to_string())
	}

	pub fn gc(&mut self, timeout: std::time::Duration) {
		let now = Instant::now();
		let mut total = 0;
		let mut removed = 0;
		self.reverse.retain(|_, v| {
			total += 1;
			if now - v.last_access < timeout {
				true
			} else {
				removed += 1;
				self.entries.remove(&v.name);
				false
			}
		});
		if removed > 0 {
			info!("gc: total {total}, removed {removed}");
		}
	}
}

pub async fn gc_task(
	mut quit_signal: oneshot::Receiver<()>,
	pool: Rc<RefCell<FakePool>>,
	timeout: Duration,
	interval: Duration,
) {
	loop {
		select! {
			_ = sleep(interval) => {
			pool.borrow_mut().gc(timeout);
			}
			_ = &mut quit_signal => {
			info!("gc exiting");
			break;
			}
		}
	}
}

pub fn ip4_to_u32(ip: Ipv4Addr) -> u32 {
	let octets = ip.octets();
	(octets[0] as u32) << 24 | (octets[1] as u32) << 16 | (octets[2] as u32) << 8 | octets[3] as u32
}

pub fn u32_to_ip4(ip: u32) -> Ipv4Addr {
	Ipv4Addr::new(
		((ip >> 24) & 0xFF) as u8,
		((ip >> 16) & 0xFF) as u8,
		((ip >> 8) & 0xFF) as u8,
		(ip & 0xFF) as u8,
	)
}
