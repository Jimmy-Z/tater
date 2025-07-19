pub const SOCKS5_VER: u8 = 5;
pub const SOCKS5_RSV: u8 = 0;

pub const SOCKS5_NO_AUTH_REQUIRED: u8 = 0;

pub const SOCKS5_CMD_CONNECT: u8 = 1;

pub const SOCKS5_ATYP_V4: u8 = 1;
pub const SOCKS5_ATYP_DOMAINNAME: u8 = 3;
pub const SOCKS5_ATYP_V6: u8 = 4;

pub const SOCKS5_REP_SUCCEED: u8 = 0;
pub const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 7;

use log::*;
use std::fmt::Display;

pub fn expect<T: Display + Eq>(name: impl Display, v: T, exp: T) -> Option<()> {
	if v != exp {
		error!("invalid {}, expecting {}, got {}", name, exp, v);
		None
	} else {
		Some(())
	}
}
