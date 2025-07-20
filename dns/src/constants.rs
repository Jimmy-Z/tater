// OpCode
pub const OPCODE_QUERY: u8 = 0;
const OPCODE_TABLE: &[&str] = &["Query", "IQuery", "Status", "Reserved"];

// RCode
pub const RCODE_NOERR: u8 = 0;
pub const RCODE_FMTERR: u8 = 1;
pub const RCODE_NOIMPL: u8 = 4;
const RCODE_TABLE: &[&str] = &[
	"NoError",
	"FormatError",
	"ServerFailure",
	"NameError",
	"NotImplemented",
	"Refused",
	"Reserved",
];

// Class
pub const CLASS_IN: u16 = 1;
const CLASS_TABLE: &[&str] = &["IN", "NotImplemented"];

// Type
pub const TYPE_A: u16 = 1;
const TYPE_TABLE: &[&str] = &["A", "NotImplemented"];

pub fn opcode2str(c: u8) -> &'static str {
	code2str(OPCODE_TABLE, OPCODE_QUERY as u16, c as u16)
}

pub fn rcode2str(c: u8) -> &'static str {
	code2str(RCODE_TABLE, RCODE_NOERR as u16, c as u16)
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
		table[table.len() - 1]
	}
}
