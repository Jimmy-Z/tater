use std::fs::read_to_string;

use log::*;

pub fn get_fake_header(path: &str) -> Vec<u8> {
	let Ok(s) = read_to_string(path).inspect_err(|e| {
		warn!(
			"error reading from {}: {}, will fallback to use an empty header",
			path, e
		)
	}) else {
		return Vec::from(b"\r\n\r\n");
	};
	let mut res = String::with_capacity(0x200);
	for l in s.lines() {
		let l = l.trim();
		if l.len() == 0 {
			continue;
		}
		res.push_str(l);
		res.push_str("\r\n");
	}
	res.push_str("\r\n");
	res.into_bytes()
}
