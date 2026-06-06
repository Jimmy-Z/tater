use std::{cell::RefCell, rc::Rc, time::Duration};

use clap::Parser;
use log::*;
use tokio::{signal::ctrl_c, sync::oneshot, task};

use tater::{
	fake_dns,
	fake_pool::{FakePool, gc_task},
	tproxy,
};


#[derive(Parser)]
#[command(version = env!("REV"))]
struct Args {
	#[clap(long, env, default_value = "100.64.0.0")]
	pub fake_pool_addr: String,
	#[clap(long, env, default_value_t = 10)]
	pub fake_pool_cidr_len: u8,
	#[clap(long, env, default_value_t = 0x1000)]
	pub fake_pool_init_cap: usize,

	#[clap(long, env, default_value_t = 7)]
	pub fake_pool_gc_interval: u64,
	#[clap(long, env, default_value_t = 3600 * 7)]
	pub fake_pool_gc_timeout: u64,

	#[clap(short, long, env, default_value = "127.0.0.1:1053")]
	pub fake_dns_listen: String,

	#[clap(short, long, env, default_value = "127.0.0.1:1090")]
	pub tproxy_listen: String,

	#[clap(short, long, env, default_value = "127.0.0.1:1080")]
	pub socks5: String,
}

#[cfg(debug_assertions)]
const LOG_LEVEL: &str = "debug";
#[cfg(not(debug_assertions))]
const LOG_LEVEL: &str = "info";

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let args = Args::parse();

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(LOG_LEVEL)).init();

	let pool = Rc::new(RefCell::new(FakePool::new(
		args.fake_pool_addr.parse().unwrap(),
		args.fake_pool_cidr_len,
		args.fake_pool_init_cap,
	)));

	let local = task::LocalSet::new();

	let (abort_tx0, abort0) = oneshot::channel();
	let (abort_tx1, abort1) = oneshot::channel();
	let (abort_tx2, abort2) = oneshot::channel();

	local.spawn_local(async move {
		ctrl_c().await.unwrap();
		info!("ctrl-c received, shutting down");
		abort_tx0.send(()).unwrap();
		abort_tx1.send(()).unwrap();
		abort_tx2.send(()).unwrap();
	});
	local.spawn_local(fake_dns(
		abort0,
		args.fake_dns_listen.parse().unwrap(),
		pool.clone(),
	));
	local.spawn_local(tproxy(
		abort1,
		args.tproxy_listen.parse().unwrap(),
		pool.clone(),
		args.socks5.parse().unwrap(),
	));
	local.spawn_local(gc_task(
		abort2,
		pool.clone(),
		Duration::from_secs(args.fake_pool_gc_timeout),
		Duration::from_secs(args.fake_pool_gc_interval),
	));

	local.await;
}
