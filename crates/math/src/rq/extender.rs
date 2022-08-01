#![warn(missing_docs, unused_imports)]

//! Context extender to switch from polynomials in R_q\[x\] into polynomials
//! in R_q\[x\] \&times R_p\[x\].

use super::{traits::ContextSwitcher, Context, Poly, Representation};
use crate::rns::{RnsContext, RnsConverter};
use itertools::{izip, Itertools};
use ndarray::{s, Array2, Axis};
use std::rc::Rc;

/// Context extender.
#[derive(Debug, Clone, PartialEq)]
pub struct Extender {
	from: Rc<Context>,
	to: Rc<Context>,
	converter: RnsConverter,
}

impl Extender {
	/// Create a context extender from a context `from` to a context `to`. The moduli used
	/// in the context `to` must be distinct from the moduli in `from`.
	pub fn new(from: &Rc<Context>, to: &Rc<Context>) -> Result<Self, &'static str> {
		if from.degree != to.degree {
			return Err("The context should be for polynomials of the same degree");
		}
		if to.q.len() <= from.q.len() {
			return Err("The to context does not extend the from context");
		}
		if from.q != to.q[..from.q.len()] {
			return Err("The moduli of from and to do not match");
		}
		for modulus in &to.q[from.q.len()..] {
			if from.q.contains(modulus) {
				return Err("The new moduli in `to` must be distinct from the moduli in `from`");
			}
		}
		let new_moduli = &to.q[from.q.len()..];
		let new_rns =
			RnsContext::new(&new_moduli.iter().map(|pi| pi.modulus()).collect_vec()).unwrap();
		let converter = RnsConverter::new(&from.rns, &new_rns);

		Ok(Self {
			from: from.clone(),
			to: to.clone(),
			converter,
		})
	}
}

impl ContextSwitcher for Extender {
	type Error = &'static str;
	fn switch_context(&self, p: &Poly) -> Result<Poly, <Self as ContextSwitcher>::Error> {
		if p.ctx.as_ref() != self.from.as_ref() {
			Err("The input polynomial does not have the correct context")
		} else if p.representation != Representation::PowerBasis {
			Err("The input polynomial should be in power basis representation")
		} else {
			let mut new_coefficients = Array2::zeros((self.to.q.len(), self.to.degree));
			new_coefficients
				.slice_mut(s![..self.from.q.len(), ..])
				.assign(&p.coefficients);

			izip!(
				new_coefficients
					.slice_mut(s![self.from.q.len().., ..])
					.axis_iter_mut(Axis(1)),
				p.coefficients.axis_iter(Axis(1))
			)
			.for_each(|(mut n_c, p_c)| {
				self.converter.convert(&p_c, &mut n_c);
			});

			Ok(Poly {
				ctx: self.to.clone(),
				representation: Representation::PowerBasis,
				coefficients: new_coefficients,
				coefficients_shoup: None,
			})
		}
	}
}

#[cfg(test)]
mod tests {
	use super::Extender;
	use crate::{
		rns::RnsContext,
		rq::{traits::ContextSwitcher, Context, Poly, Representation},
	};
	use num_bigint::BigUint;
	use std::rc::Rc;

	// Moduli to be used in tests.
	static Q: &[u64; 3] = &[
		4611686018282684417,
		4611686018326724609,
		4611686018309947393,
	];
	static P: &[u64; 5] = &[
		1153,
		4611686018257518593,
		4611686018232352769,
		4611686018171535361,
		4611686018106523649,
	];

	#[test]
	fn test_constructor() {}

	#[test]
	fn test_extender() {
		let ntests = 100;
		let from = Rc::new(Context::new(Q, 8).unwrap());
		let mut all_moduli = Q.to_vec();
		all_moduli.append(&mut P.to_vec());
		let to = Rc::new(Context::new(&all_moduli, 8).unwrap());

		let extender = Extender::new(&from, &to);
		assert!(extender.is_ok());
		let extender = extender.unwrap();

		for _ in 0..ntests {
			let poly = Poly::random(&from, Representation::PowerBasis);
			let poly_biguint = Vec::<BigUint>::from(&poly);

			let extended_poly = extender.switch_context(&poly);
			assert!(extended_poly.is_ok());
			let extended_poly = extended_poly.unwrap();

			let mut expected_biguint = poly_biguint.clone();
			let rns = RnsContext::new(&all_moduli).unwrap();
			for c in &mut expected_biguint {
				// If this is a negative coefficient, set the expected biguint
				// with regard to the large modulus instead.
				if *c >= (poly.ctx.rns.modulus() >> 1usize) {
					*c += rns.modulus() - poly.ctx.rns.modulus()
				}
			}
			assert_eq!(expected_biguint, Vec::<BigUint>::from(&extended_poly));
		}
	}
}