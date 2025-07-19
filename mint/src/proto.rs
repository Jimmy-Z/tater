use aead::{AeadCore, AeadInPlace, KeyInit, Nonce, OsRng as AeadOsRng};
use bytes::{BufMut, BytesMut};
use log::*;
use rand::{Rng as _, TryRngCore as _, rngs::OsRng};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy, split};

const EOH: &[u8] = b"\r\n\r\n";

const VER: u8 = 0;
const REP_OK: u8 = 0;

pub async fn client_handshake<
	T: AsyncRead + AsyncWrite + Unpin,
	C: KeyInit + AeadCore + AeadInPlace,
>(
	io: &mut T,
	cipher: &C,
	buf: &mut BytesMut,
	host: &str,
	port: u16,
	header: &[u8],
) -> Option<()> {
	buf.clear();
	write_msg(buf, cipher, header, &Req(host, port));
	io.write_all(buf)
		.await
		.map_err(|e| debug!("handshake error writing: {}", e))
		.ok()?;

	buf.clear();
	io.read_buf(buf)
		.await
		.map_err(|e| debug!("handshake error reading: {}", e))
		.ok()?;
	let Some(resp): Option<Resp> = read_msg(buf, cipher) else {
		return None;
	};

	if resp.0 != REP_OK {
		debug!("server replies 0x{:02x}, unexpected", resp.0);
		return None;
	}

	Some(())
}

pub async fn server_handshake<
	T: AsyncRead + AsyncWrite + Unpin,
	C: KeyInit + AeadCore + AeadInPlace,
>(
	io: &mut T,
	cipher: &C,
	buf: &mut BytesMut,
	header: &[u8],
) -> Option<(String, u16)> {
	buf.clear();
	io.read_buf(buf)
		.await
		.map_err(|e| debug!("handshake error reading: {}", e))
		.ok()?;
	let Some(req): Option<Req> = read_msg(buf, cipher) else {
		return None;
	};

	let host = req.0.to_owned();
	let port = req.1;

	buf.clear();
	write_msg(buf, cipher, header, &Resp(REP_OK));
	io.write_all(buf)
		.await
		.map_err(|e| debug!("handshake error writing: {}", e))
		.ok()?;

	// debug!("buf capacity: {}", buf.capacity());
	Some((host, port))
}

// can't be implemented on BufMut since we want encrypt in place
fn write_msg<'a, C: AeadCore + AeadInPlace>(
	buf: &mut BytesMut,
	cipher: &C,
	header: &[u8],
	payload: &impl Payload<'a>,
) {
	buf.put_slice(header);

	let nonce = C::generate_nonce(&mut AeadOsRng);
	buf.put_slice(&nonce);

	let payload_offset = buf.len();

	payload.write(&mut *buf);

	// padding
	buf.put_bytes(
		OsRng.unwrap_err().random(),
		OsRng.unwrap_err().random_range(0x200..0x300),
	);

	let mut payload = buf.split_off(payload_offset);

	cipher.encrypt_in_place(&nonce, b"", &mut payload).unwrap();

	buf.unsplit(payload);
}

fn read_msg<'a, C: AeadCore + AeadInPlace, T: Payload<'a>>(
	buf: &'a mut BytesMut,
	cipher: &C,
) -> Option<T> {
	let Some(eoh) = buf.as_ref().windows(EOH.len()).position(|w| w == EOH) else {
		debug!("EoH not found, unexpected");
		return None;
	};

	let nonce_offset = eoh + EOH.len();

	let payload_offset = nonce_offset + nonce_size::<C>();
	if buf.len() < payload_offset {
		if buf.len() == nonce_offset {
			debug!("invalid msg, likely just HTTP");
		} else {
			debug!("invalid msg, no nonce");
		}
		return None;
	}
	let mut payload = buf.split_off(payload_offset);
	if let Err(e) = cipher.decrypt_in_place(
		&Nonce::<C>::from_slice(&buf[nonce_offset..nonce_offset + nonce_size::<C>()]),
		b"",
		&mut payload,
	) {
		debug!("failed to decrypt message, likely invalid: {}", e);
		return None;
	}
	buf.unsplit(payload);

	Payload::read(&buf[payload_offset..])
}

trait Payload<'a>: Sized {
	fn write(&self, buf: impl BufMut);
	fn read(buf: &'a [u8]) -> Option<Self>;
}

#[derive(Debug, PartialEq, Eq)]
struct Req<'a>(&'a str, u16);

#[derive(Debug, PartialEq, Eq)]
struct Resp(u8);

impl<'a> Payload<'a> for Req<'a> {
	fn write(&self, mut buf: impl BufMut) {
		buf.put_u8(VER);
		buf.put_u8(self.0.len() as u8);
		buf.put_slice(self.0.as_bytes());
		buf.put_u16(self.1);
	}
	fn read(buf: &'a [u8]) -> Option<Self> {
		if buf.len() < 2 {
			error!("invalid request length: {}", buf.len());
			return None;
		}
		let ver = buf[0];
		if ver != VER {
			error!("invalid ver: 0x{:02x}", ver);
			return None;
		}
		let len = buf[1];
		if buf.len() < 2 + len as usize + 2 {
			error!(
				"invalid request length: {} < {}",
				buf.len(),
				2 + len as usize + 2
			);
			return None;
		}
		let Ok(host) = str::from_utf8(&buf[2..2 + len as usize]) else {
			error!("invalid utf8 in host");
			return None;
		};
		let port = u16::from_be_bytes(
			buf[2 + len as usize..2 + len as usize + 2]
				.try_into()
				.unwrap(),
		);
		Some(Req(host, port))
	}
}

impl<'a> Payload<'a> for Resp {
	fn write(&self, mut buf: impl BufMut) {
		buf.put_u8(self.0);
	}
	fn read(buf: &'a [u8]) -> Option<Self> {
		if buf.len() < 1 {
			error!("invalid response length: {}", buf.len());
			return None;
		}
		Some(Resp(buf[0]))
	}
}

// read once from the plain side, encrypt it, write it to the encrypted side
async fn enc1<C: AeadCore + AeadInPlace, E: AsyncWrite + Unpin, P: AsyncRead + Unpin>(
	buf: &mut BytesMut,
	cipher: &C,
	encrypted: &mut E,
	plain: &mut P,
) -> Option<()> {
	buf.clear();

	// we don't generate nonce at this point
	buf.put_bytes(0, nonce_size::<C>());

	// we don't have length yet
	buf.put_u16(0);
	let payload_offset = buf.len();

	if let Err(e) = plain.read_buf(buf).await {
		debug!("failed to read plain data: {}", e);
		return None;
	}
	let mut payload = buf.split_off(payload_offset);
	if payload.is_empty() {
		debug!("got 0 reading plain data, likely remote closed");
		buf.unsplit(payload);
		return None;
	}

	let nonce = C::generate_nonce(&mut AeadOsRng);
	if let Err(e) = cipher.encrypt_in_place(&nonce, b"", &mut payload) {
		error!("failed to encrypt: {}", e);
		return None;
	}
	// write nonce
	(&mut buf[..nonce_size::<C>()]).copy_from_slice(&nonce);
	// write length
	let len = obfuscate(payload.len() as u16, &nonce).to_be_bytes();
	(&mut buf[nonce_size::<C>()..]).copy_from_slice(&len);
	buf.unsplit(payload);

	encrypted
		.write_all(buf)
		.await
		.inspect_err(|e| debug!("failed to write encrypted data: {}", e))
		.ok()
}

// read one _packet_ from the encrypted side, decrypt it, write it to the plain side
async fn dec1<C: AeadCore + AeadInPlace, P: AsyncWrite + Unpin, E: AsyncRead + Unpin>(
	buf: &mut BytesMut,
	cipher: &C,
	plain: &mut P,
	encrypted: &mut E,
) -> Option<()> {
	let mut nonce = Nonce::<C>::default();
	if let Err(e) = encrypted.read_exact(&mut nonce).await {
		debug!("failed to read nonce: {}", e);
		return None;
	}

	let len = encrypted
		.read_u16()
		.await
		.map_err(|e| debug!("failed to read len: {}", e))
		.ok()?;
	let len = obfuscate(len, &nonce);
	if len == 0 {
		debug!("length = 0, unexpected");
		return None;
	}

	buf.resize(len as usize, 0);

	if let Err(e) = encrypted.read_exact(buf).await {
		error!("failed to read payload: {}", e);
		return None;
	}

	if let Err(e) = cipher.decrypt_in_place(&nonce, b"", buf) {
		error!("failed to decrypt payload: {}", e);
		return None;
	}

	plain
		.write_all(buf)
		.await
		.map_err(|e| {
			error!("failed to write decrypted payload: {}", e);
		})
		.ok()
}

pub async fn duplex<
	C: AeadCore + AeadInPlace,
	P: AsyncRead + AsyncWrite + Unpin,
	E: AsyncRead + AsyncWrite + Unpin,
>(
	cipher: &C,
	plain: &mut P,
	encrypted: &mut E,
) {
	let (mut p_r, mut p_w) = split(plain);
	let (mut e_r, mut e_w) = split(encrypted);
	tokio::join!(
		simplex(cipher, enc1, &mut e_w, &mut p_r),
		simplex(cipher, dec1, &mut p_w, &mut e_r),
	);
}

pub async fn simplex<
	C: AeadCore + AeadInPlace,
	F: AsyncFn(&mut BytesMut, &C, &mut W, &mut R) -> Option<()>,
	W: AsyncWrite + Unpin,
	R: AsyncRead + Unpin,
>(
	cipher: &C,
	codec: F,
	w: &mut W,
	r: &mut R,
) -> Option<()> {
	// enclosed so I can use ? and still guarantee shutdown
	// is there a better pattern?
	async {
		let mut buf = BytesMut::with_capacity(0x1000);
		codec(&mut buf, cipher, w, r).await?;
		codec(&mut buf, cipher, w, r).await?;
		codec(&mut buf, cipher, w, r).await?;
		drop(buf);
		copy(r, w)
			.await
			.inspect_err(|e| debug!("error copying: {}", e))
			.ok()
	}
	.await;
	w.shutdown()
		.await
		.inspect_err(|e| debug!("error shutting down: {}", e))
		.ok()
}

// is there a less verbose way?
const fn nonce_size<C: AeadCore>() -> usize {
	std::mem::size_of::<Nonce<C>>()
}

// make len look random
fn obfuscate(a: u16, b: &[u8]) -> u16 {
	a ^ u16::from_be_bytes([b[4 % b.len()], b[2 % b.len()]])
}

#[cfg(test)]
mod test {
	use bytes::BytesMut;
	use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, aead::OsRng};

	use super::*;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	#[test]
	fn test_payload() {
		init();

		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		println!("key len: {}", key.len());
		let cipher = ChaCha20Poly1305::new(&key);
		let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
		println!("nonce len: {}", nonce.len());
		assert_eq!(nonce.len(), nonce_size::<ChaCha20Poly1305>());

		let mut buf = BytesMut::with_capacity(1024);
		let req = Req("example.com", 443);
		write_msg(&mut buf, &cipher, EOH, &req);
		let req_r: Req = read_msg(&mut buf, &cipher).unwrap();
		assert_eq!(req, req_r);
	}

	#[tokio::test]
	async fn test_handshake() {
		init();

		let (mut c, mut s) = tokio::io::duplex(0x500);

		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		let cipher = ChaCha20Poly1305::new(&key);

		tokio::join!(
			async {
				let mut buf = BytesMut::with_capacity(0x500);
				assert_eq!(
					Some(()),
					client_handshake(&mut c, &cipher, &mut buf, "example.com", 443, EOH).await
				);
			},
			async {
				let mut buf = BytesMut::with_capacity(0x500);
				assert_eq!(
					Some(("example.com".to_owned(), 443)),
					server_handshake(&mut s, &cipher, &mut buf, EOH).await
				);
			}
		);
	}

	#[tokio::test]
	async fn test_enc() {
		init();

		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		let cipher = ChaCha20Poly1305::new(&key);

		let mut buf = BytesMut::with_capacity(0x100);
		let (mut b, mut a) = tokio::io::simplex(0x100);
		let (mut d, mut c) = tokio::io::simplex(0x100);

		let test_payload = b"you're (not) welcome.";
		a.write_all(test_payload).await.unwrap();

		enc1(&mut buf, &cipher, &mut c, &mut b).await.unwrap();

		dec1(&mut buf, &cipher, &mut a, &mut d).await.unwrap();

		buf.clear();
		b.read_buf(&mut buf).await.unwrap();

		assert_eq!(test_payload, &buf[..]);
	}
}
