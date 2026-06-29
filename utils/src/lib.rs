mod pretty;

pub use pretty::Pretty;

use time::{
	OffsetDateTime, format_description::StaticFormatDescription, macros::format_description,
};
use toml::Table;

use std::{collections::HashMap, fs::read_to_string, str::FromStr};

const FMT: StaticFormatDescription = format_description!(
	"[year]-[month]-[day] [hour]:[minute]:[second] UTC[offset_hour sign:mandatory]:[offset_minute]"
);

// to do: std::net::hostname is still nightly-only
pub fn comp_time_env_rev(deps: &[&str]) {
	let mut env = String::with_capacity(0x1000);

	let rev = option_env!("GIT_REV_SHORT").unwrap_or("unknown");
	let now = OffsetDateTime::now_local().unwrap();
	env.push_str(&format!(
		"cargo::rustc-env=REV=rev-{} {}",
		rev,
		now.format(&FMT).unwrap()
	));

	if !deps.is_empty() {
		let lock = Table::from_str(&read_to_string("../Cargo.lock").unwrap()).unwrap();
		let mut vers = HashMap::with_capacity(deps.len());
		for pkg in lock["package"].as_array().unwrap() {
			let pkg = pkg.as_table().unwrap();
			let name = pkg["name"].as_str().unwrap();
			if deps.contains(&name) {
				vers.insert(name, pkg["version"].as_str().unwrap());
			}
		}
		for dep in deps {
			env.push_str(&format!(", {dep} {}", vers.get(dep).unwrap()));
		}
	}

	println!("{}", env);
}
