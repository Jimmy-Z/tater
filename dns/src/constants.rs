pub const DNS_HEADER_LEN: usize = 12;

// byte offset, bit offset, name, for easier enumeration/display only
// caution: in rfc1035 4.1.1 (and rfc6895 2), 0 actually denotes the highest bit
// ad and cd are introduced in rfc2535 6.7
pub const FLAGS: &[(u8, u8, &str)] = &[
	(2, 7, "qr"), // query or response
	// 4 bits gap here is opcode
	(2, 2, "aa"), // authoritative answer
	(2, 1, "tc"), // truncated
	(2, 0, "rd"), // recursive desired
	(3, 7, "ra"), // recursive available
	(3, 6, "z"),  // zero
	(3, 5, "ad"), // authentic data
	(3, 4, "cd"), // checking disabled
];
// 4 bits afterwards is rcode

// OpCode
pub const OPCODE_QUERY: u8 = 0;
const OPCODE_TABLE: &[&str] = &["Query"];

// RCode
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_NOTIMP: u8 = 4;
const RCODE_TABLE: &[&str] = &[
	"NoError", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused",
];

// Class
pub const CLASS_IN: u16 = 1;
const CLASS_TABLE: &[&str] = &["IN"];

// Type
pub const TYPE_A: u16 = 1;
const TYPE_TABLE: &[&str] = &["A"];

pub fn opcode2str(c: u8) -> &'static str {
	code2str(OPCODE_TABLE, OPCODE_QUERY as u16, c as u16)
}

pub fn rcode2str(c: u8) -> &'static str {
	code2str(RCODE_TABLE, RCODE_NOERROR as u16, c as u16)
}

pub fn class2str(c: u16) -> &'static str {
	code2str(CLASS_TABLE, CLASS_IN, c)
}

pub fn type2str(c: u16) -> &'static str {
	code2str(TYPE_TABLE, TYPE_A, c)
}

fn code2str(table: &'static [&'static str], base: u16, c: u16) -> &'static str {
	let c = (c - base) as usize;
	if c < table.len() {
		table[c]
	} else {
		"NotImplemented"
	}
}
