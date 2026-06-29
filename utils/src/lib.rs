mod pretty;

pub use pretty::Pretty;

use time::{
	OffsetDateTime, format_description::StaticFormatDescription, macros::format_description,
};

const FMT: StaticFormatDescription = format_description!(
	"[year]-[month]-[day] [hour]:[minute]:[second] UTC[offset_hour sign:mandatory]:[offset_minute]"
);

// to do: std::net::hostname is still nightly-only
pub fn comp_time_env_rev() {
	let rev = option_env!("GIT_REV_SHORT").unwrap_or("unknown");
	let now = OffsetDateTime::now_local().unwrap();
	println!(
		"cargo::rustc-env=REV=rev-{}, built on: {}",
		rev,
		now.format(&FMT).unwrap()
	);
}
