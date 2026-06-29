use log::*;

use base64::prelude::{BASE64_STANDARD_NO_PAD as BASE64, Engine as _};
use chacha20poly1305::aead::{Generate as _, Key, KeyInit, KeySizeUser};

pub fn gen_psk<C: KeySizeUser>() -> String {
	let key = Key::<C>::generate();
	BASE64.encode(key.as_slice())
}

pub fn init_cipher<C: KeyInit>(key_path: &str) -> Option<C> {
	let key = std::fs::read(key_path)
		.inspect_err(|e| error!("failed to read \"{key_path}\": {e}"))
		.ok()?;
	let key = BASE64
		.decode((&key as &[u8]).trim_ascii())
		.inspect_err(|e| error!("failed to decode base64: {e}"))
		.ok()?;
	C::new_from_slice(&key)
		.inspect_err(|e| error!("failed to create cipher: {e}"))
		.ok()
}
