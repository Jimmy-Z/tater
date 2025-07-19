// https://datatracker.ietf.org/doc/html/rfc1928

mod addr;
mod client;
mod common;
mod server;

pub use addr::Dst;
pub use client::client_handshake;
pub use server::server_handshake;

#[cfg(test)]
mod tests {
	use super::*;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	#[tokio::test]
	async fn test() {
		init();

		let (mut c, mut s) = tokio::io::duplex(0x100);

		let test_dst: Dst = ("example.com", 443).into();

		tokio::join!(
			async {
				let r = client_handshake(&mut c, &test_dst).await;
				assert_eq!(r, Some(()));
			},
			async {
				let r = server_handshake(&mut s).await;
				assert!(r.is_some());
				assert_eq!(r.unwrap(), test_dst);
			}
		);
	}
}
