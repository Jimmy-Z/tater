use std::fmt::Display;

pub struct Pretty<T>(pub T);

const SI_PREFIXES: [&str; 5] = ["", "K", "M", "G", "T"];

impl Display for Pretty<usize> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		fmt_f32(self.0 as f32, f)
	}
}

fn fmt_f32(mut v: f32, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
	let mut e = 0;
	while v >= 1000.0 {
		v /= 1000.0;
		e += 1;
	}
	// always 3 significants
	if v >= 100.0 {
		write!(f, "{:.0} {}", v, SI_PREFIXES[e])
	} else if v >= 10.0 {
		write!(f, "{:.1} {}", v, SI_PREFIXES[e])
	} else {
		write!(f, "{:.2} {}", v, SI_PREFIXES[e])
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pretty() {
		assert_eq!(format!("{}", Pretty(42)), "42.0 ");
		assert_eq!(format!("{}", Pretty(1984)), "1.98 K");
	}
}
