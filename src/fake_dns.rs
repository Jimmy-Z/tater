use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use hickory_proto::{
	op::{Header, Message, MessageType, Query, ResponseCode},
	rr::{rdata::a::A, DNSClass, RData, Record, RecordType},
};
use log::*;
use tokio::{net::UdpSocket, select, sync::oneshot};

use crate::fake_pool::FakePool;

pub async fn fake_dns(
	mut quit_signal: oneshot::Receiver<()>,
	listen: SocketAddr,
	pool: Rc<RefCell<FakePool>>,
) {
	let s = Rc::new(UdpSocket::bind(listen).await.unwrap());
	info!("listening on UDP {}", s.local_addr().unwrap());

	let mut buf = vec![0u8; 0x600];
	loop {
		select! {
			r = s.recv_from(&mut buf) => {
				match r {
					Ok((len, addr)) => {
						trace!("udp recv {} bytes from {}", len, addr);
						let resp = fake_resolve(&buf[..len], pool.clone());
						if resp.is_none() {
							continue;
						}
						match s.send_to(&resp.unwrap(), addr).await {
							Ok(len) => {
								trace!("udp send {} bytes to {}", len, addr);
							}
							Err(e) => {
								error!("udp send error: {}", e);
								break;
							}
						}
					}
					Err(e) => {
						error!("udp recv error: {}", e);
						break;
					}
				}
			}
			// to my surprise, &mut works
			_ = &mut quit_signal => {
				info!("exiting");
				break;
			}
		}
	}
}

fn fake_resolve(q_buf: &[u8], pool: Rc<RefCell<FakePool>>) -> Option<Vec<u8>> {
	let req = Message::from_vec(q_buf)
		.map_err(|e| error!("parse error: {}", e))
		.ok()?;
	trace!("dns query: {}", req);

	let qh = req.header();
	let mut h = Header::response_from_request(qh);

	if qh.message_type() != MessageType::Query || qh.query_count() != 1 {
		debug!(
			"expecting query, got {}, query count {}",
			qh.message_type(),
			qh.query_count()
		);
		h.set_response_code(ResponseCode::FormErr);
		return mk_resp(h, None, None);
	}

	let q = req.queries().first()?;

	if q.query_class() != DNSClass::IN || q.query_type() != RecordType::A {
		info!("unsupported query: {} {}", q.query_class(), q.query_type());
		h.set_response_code(ResponseCode::NotImp);
		return mk_resp(h, Some(q), None);
	}

	let q_name = q.name().to_ascii();
	let q_name = q_name.trim_end_matches('.');
	let addr = pool.borrow_mut().get(q_name);
	let mut a: Record = Record::with(q.name().to_owned(), RecordType::A, 0);
	a.set_data(Some(RData::A(A(addr))));

	mk_resp(h, Some(q), Some(a))
}

fn mk_resp(header: Header, q: Option<&Query>, answer: Option<Record>) -> Option<Vec<u8>> {
	let mut resp = Message::new();
	resp.set_header(header);
	if let Some(q) = q {
		resp.add_query(q.to_owned());
	}
	if let Some(a) = answer {
		resp.add_answer(a);
	}
	// it seems finalize() is not necessary
	trace!("dns response: {}", resp);
	resp.to_vec()
		.map_err(|e| error!("dns response encode error: {}", e))
		.ok()
}
