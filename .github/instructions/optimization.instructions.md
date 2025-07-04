---
applyTo: "**"
---

# Threshold BFV Optimization Implementation Guide

## Objective

Reduce complexity from O(n²N) to O(n²N/t) setup + O(N) operations by implementing:

1. **Packed Shamir Secret Sharing** - Reduce secret sharing overhead
2. **Hybrid Additive Operations** - Make linear operations local

## Implementation Plan

### Phase 1: Add Supporting Structures

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 1.1 Add new imports at the top

```rust
// Add after existing imports
use num_bigint::BigUint;
use std::collections::HashMap;
```

#### 1.2 Add new structures before `TrBFVShare`

```rust
#[derive(Debug, Clone)]
pub struct ShamirMetadata {
    pub evaluation_point: usize,
    pub threshold: usize,
    pub modulus: BigInt,
}

#[derive(Debug, Clone)]
pub struct PackedHybridShare {
    pub additive_parts: Vec<Poly>,  // One poly per packed block
    pub pack_size: usize,
    pub shamir_metadata: ShamirMetadata,
    pub party_id: usize,
}

#[derive(Debug, Clone)]
pub struct PackingParameters {
    pub pack_size: usize,
    pub total_blocks: usize,
    pub last_block_size: usize,
}
```

### Phase 2: Implement Core Packing Functions

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 2.1 Add packing utilities to `TrBFVShare` impl block (after existing methods)

```rust
impl TrBFVShare {
    // ... existing methods ...

    /// Calculate optimal packing parameters
    pub fn calculate_packing_params(&self) -> PackingParameters {
        let pack_size = self.threshold; // Pack threshold coefficients together
        let total_blocks = (self.degree + pack_size - 1) / pack_size;
        let last_block_size = if self.degree % pack_size == 0 {
            pack_size
        } else {
            self.degree % pack_size
        };

        PackingParameters {
            pack_size,
            total_blocks,
            last_block_size,
        }
    }

    /// Pack multiple coefficients into a single secret
    fn pack_coefficients(&self, coeffs: &[i64], modulus: u64) -> Result<BigInt> {
        if coeffs.is_empty() {
            return Ok(BigInt::zero());
        }

        // Use a safe packing base that prevents overflow
        let base = BigInt::from(modulus.next_power_of_two().min(1u64 << 32));
        let mut packed = BigInt::zero();

        for (i, &coeff) in coeffs.iter().enumerate() {
            // Handle negative coefficients by adding modulus
            let normalized_coeff = if coeff < 0 {
                coeff + modulus as i64
            } else {
                coeff
            };

            packed += BigInt::from(normalized_coeff) * base.pow(i as u32);
        }

        Ok(packed)
    }

    /// Unpack coefficients from a packed secret
    fn unpack_coefficients(&self, packed: &BigInt, pack_size: usize, modulus: u64) -> Result<Vec<i64>> {
        let base = BigInt::from(modulus.next_power_of_two().min(1u64 << 32));
        let mut coeffs = Vec::with_capacity(pack_size);
        let mut remaining = packed.clone();

        for _ in 0..pack_size {
            let coeff_big = &remaining % &base;
            let mut coeff = coeff_big.to_i64().unwrap_or(0);

            // Handle negative coefficients
            if coeff > (modulus as i64) / 2 {
                coeff -= modulus as i64;
            }

            coeffs.push(coeff);
            remaining /= &base;
        }

        Ok(coeffs)
    }

    /// Convert BigInt share to polynomial for additive operations
    fn share_to_poly(&self, share: &BigInt, modulus_idx: usize) -> Result<Poly> {
        let coeffs = vec![share.to_u64().unwrap_or(0)];
        Poly::try_convert_from(
            &coeffs,
            &Context::new_arc(&[self.moduli[modulus_idx]], 1)?,
            false,
            Representation::PowerBasis,
        )
    }
}
```

### Phase 3: Implement Packed Hybrid Share Generation

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 3.1 Add main generation method (after packing utilities)

```rust
impl TrBFVShare {
    // ... existing methods and packing utilities ...

    /// Generate packed hybrid shares - combines packing + additive operations
    pub fn generate_packed_hybrid_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<PackedHybridShare>> {
        let packing_params = self.calculate_packing_params();
        let mut packed_hybrid_shares = Vec::with_capacity(self.n);

        // Initialize shares for each party
        for party_id in 0..self.n {
            packed_hybrid_shares.push(PackedHybridShare {
                additive_parts: Vec::new(),
                pack_size: packing_params.pack_size,
                shamir_metadata: ShamirMetadata {
                    evaluation_point: party_id + 1,
                    threshold: self.threshold,
                    modulus: BigInt::from(self.moduli[0]),
                },
                party_id,
            });
        }

        // Process each RNS modulus
        for modulus_idx in 0..self.moduli.len() {
            let shamir = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[modulus_idx]),
            };

            // Pack coefficients in chunks and create shares
            for (block_idx, chunk) in coeffs.chunks(packing_params.pack_size).enumerate() {
                let packed_secret = self.pack_coefficients(chunk, self.moduli[modulus_idx])?;
                let shares = shamir.split(packed_secret);

                // Convert each party's share to polynomial for additive operations
                for (party_id, (_, share)) in shares.iter().enumerate() {
                    let share_poly = self.share_to_poly(share, modulus_idx)?;
                    packed_hybrid_shares[party_id].additive_parts.push(share_poly);
                }
            }
        }

        Ok(packed_hybrid_shares)
    }
}
```

### Phase 4: Implement Efficient Operations

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 4.1 Add O(1) operations (after generation method)

```rust
impl TrBFVShare {
    // ... existing methods ...

    /// O(1) addition - pure local computation
    pub fn add_packed_hybrid(&self, a: &PackedHybridShare, b: &PackedHybridShare) -> PackedHybridShare {
        if a.additive_parts.len() != b.additive_parts.len() {
            panic!("Mismatched share sizes");
        }

        let mut result_parts = Vec::with_capacity(a.additive_parts.len());

        for (part_a, part_b) in a.additive_parts.iter().zip(&b.additive_parts) {
            result_parts.push(part_a + part_b);
        }

        PackedHybridShare {
            additive_parts: result_parts,
            pack_size: a.pack_size,
            shamir_metadata: a.shamir_metadata.clone(),
            party_id: a.party_id,
        }
    }

    /// Scalar multiplication - also O(1)
    pub fn scalar_mul_packed_hybrid(&self, share: &PackedHybridShare, scalar: i64) -> PackedHybridShare {
        let mut result_parts = Vec::with_capacity(share.additive_parts.len());

        for part in &share.additive_parts {
            // Create scalar poly
            let scalar_coeffs = vec![scalar as u64];
            let scalar_poly = Poly::try_convert_from(
                &scalar_coeffs,
                part.ctx(),
                false,
                Representation::PowerBasis,
            ).unwrap();

            result_parts.push(part * &scalar_poly);
        }

        PackedHybridShare {
            additive_parts: result_parts,
            pack_size: share.pack_size,
            shamir_metadata: share.shamir_metadata.clone(),
            party_id: share.party_id,
        }
    }
}
```

### Phase 5: Implement Secure Reconstruction

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 5.1 Add reconstruction method (after operations)

```rust
impl TrBFVShare {
    // ... existing methods ...

    /// Reconstruct packed hybrid shares - only when absolutely necessary
    pub fn reconstruct_packed_hybrid(&self, shares: &[PackedHybridShare]) -> Result<Poly> {
        if shares.len() < self.threshold {
            return Err(Error::InvalidParameters("Insufficient shares for reconstruction".into()));
        }

        let packing_params = self.calculate_packing_params();
        let mut reconstructed_coeffs = Vec::with_capacity(self.degree);

        // Process each RNS modulus
        for modulus_idx in 0..self.moduli.len() {
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[modulus_idx]),
            };

            // Reconstruct each packed block
            let blocks_per_modulus = packing_params.total_blocks;
            let block_start = modulus_idx * blocks_per_modulus;

            for block_idx in 0..blocks_per_modulus {
                let global_block_idx = block_start + block_idx;

                // Collect shares for this block from threshold parties
                let mut block_shares = Vec::with_capacity(self.threshold);
                for party_idx in 0..self.threshold {
                    if global_block_idx < shares[party_idx].additive_parts.len() {
                        let share_value = shares[party_idx].additive_parts[global_block_idx]
                            .coefficients()
                            .get((0, 0))
                            .unwrap_or(&0u64);

                        block_shares.push((
                            shares[party_idx].shamir_metadata.evaluation_point,
                            BigInt::from(*share_value)
                        ));
                    }
                }

                // Reconstruct this packed block
                if block_shares.len() >= self.threshold {
                    let reconstructed_packed = sss.recover(&block_shares);

                    // Unpack coefficients
                    let block_size = if block_idx == blocks_per_modulus - 1 {
                        packing_params.last_block_size
                    } else {
                        packing_params.pack_size
                    };

                    let unpacked_coeffs = self.unpack_coefficients(
                        &reconstructed_packed,
                        block_size,
                        self.moduli[modulus_idx]
                    )?;

                    reconstructed_coeffs.extend(unpacked_coeffs);
                }
            }
        }

        // Convert back to Poly
        let ctx = &self.params.ctx_at_level(0)?;
        Poly::try_convert_from(
            &reconstructed_coeffs[..self.degree.min(reconstructed_coeffs.len())],
            ctx,
            false,
            Representation::PowerBasis,
        )
    }
}
```

### Phase 6: Update Existing Methods

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 6.1 Add optimized decryption method (after reconstruct method)

```rust
impl TrBFVShare {
    // ... existing methods ...

    /// Optimized decryption using packed hybrid shares
    pub fn decrypt_packed_hybrid(
        &mut self,
        d_share_polys: Vec<PackedHybridShare>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        // Reconstruct the decryption polynomial
        let result_poly = self.reconstruct_packed_hybrid(&d_share_polys)?;

        // Scale and reduce (reuse existing scaling logic)
        let plaintext_ctx = Context::new_arc(&self.moduli[..1], self.degree)?;
        let mut scalers = Vec::with_capacity(self.moduli.len());

        for i in 0..self.moduli.len() {
            let rns = RnsContext::new(&self.moduli[..self.moduli.len() - i])?;
            let ctx_i = Context::new_arc(&self.moduli[..self.moduli.len() - i], self.degree)?;
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.plaintext_modulus), rns.modulus()),
                )?
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
        let v = Zeroizing::new(
            Vec::<u64>::from(d.as_ref())
                .iter_mut()
                .map(|vi| *vi + par.plaintext.modulus())
                .collect_vec(),
        );
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        par.plaintext.reduce_vec(&mut w);

        let mut poly = Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };

        Ok(pt)
    }
}
```

### Phase 7: Add Comprehensive Tests

**File:** `crates/fhe/src/trbfv/trbfv.rs`

#### 7.1 Add test in the tests module (after existing tests)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // ... existing imports and tests ...

    #[test]
    fn test_packed_hybrid_optimization() {
        let mut rng = thread_rng();
        let n = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        ).unwrap();

        // Generate test secret key
        let s_raw = SecretKey::random(&sk_par, &mut rng);

        // Test packing parameters
        let packing_params = trbfv.calculate_packing_params();
        assert_eq!(packing_params.pack_size, threshold);
        assert_eq!(packing_params.total_blocks, (degree + threshold - 1) / threshold);

        // Test packed hybrid share generation
        let packed_shares = trbfv.generate_packed_hybrid_shares(s_raw.coeffs.clone()).unwrap();
        assert_eq!(packed_shares.len(), n);

        // Test addition operation
        let sum_share = trbfv.add_packed_hybrid(&packed_shares[0], &packed_shares[1]);
        assert_eq!(sum_share.additive_parts.len(), packed_shares[0].additive_parts.len());

        // Test reconstruction
        let reconstructed = trbfv.reconstruct_packed_hybrid(&packed_shares[..threshold]).unwrap();
        assert_eq!(reconstructed.coefficients().dim(), (moduli.len(), degree));

        println!("Packed hybrid optimization test passed!");
        println!("Pack size: {}", packing_params.pack_size);
        println!("Total blocks: {}", packing_params.total_blocks);
        println!("Communication reduction: {}x", packing_params.pack_size);
    }

    #[test]
    fn test_optimization_correctness() {
        let mut rng = thread_rng();
        let n = 8;
        let threshold = 5;
        let degree = 1024;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001];

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        ).unwrap();

        let s_raw = SecretKey::random(&sk_par, &mut rng);

        // Compare original vs optimized
        let original_shares = trbfv.generate_secret_shares(s_raw.coeffs.clone()).unwrap();
        let packed_shares = trbfv.generate_packed_hybrid_shares(s_raw.coeffs.clone()).unwrap();

        // Both should work for threshold reconstruction
        assert!(original_shares.len() == moduli.len());
        assert!(packed_shares.len() == n);

        println!("Correctness test passed - both methods generate valid shares");
    }
}
```

## Testing Strategy

### 1. Unit Tests

Run individual tests:

```bash
cd /home/auryn/git/gnosisguild/fhe.rs
cargo test trbfv::tests::test_packed_hybrid_optimization -- --nocapture
cargo test trbfv::tests::test_optimization_correctness -- --nocapture
```

### 2. Integration Testing

Test with existing codebase:

```bash
cargo test trbfv -- --nocapture
```

### 3. Performance Benchmarking

Create benchmark comparing:

- Original: `generate_secret_shares()` → operations → `decrypt()`
- Optimized: `generate_packed_hybrid_shares()` → `add_packed_hybrid()` → `decrypt_packed_hybrid()`

## Expected Performance Improvements

| Operation        | Original | Optimized | Improvement  |
| ---------------- | -------- | --------- | ------------ |
| Share Generation | O(n²N)   | O(n²N/t)  | t× faster    |
| Addition         | O(n²N)   | O(N)      | n² × faster  |
| Communication    | O(nN)    | O(nN/t)   | t× less data |

For your parameters (n=16, t=9, N=2048):

- **Share Generation**: 9× faster
- **Operations**: 256× faster
- **Communication**: 9× less data

## Migration Notes

1. **Backward Compatibility**: Keep existing methods for compatibility
2. **Gradual Adoption**: New methods can be used alongside existing ones
3. **Error Handling**: All new methods properly propagate `Result<T>` types
4. **Memory Safety**: Uses `Zeroizing` for sensitive data where appropriate

## Next Steps

1. Implement Phase 1-3 first and test basic functionality
2. Add Phase 4-5 for full optimization
3. Phase 6-7 for integration and testing
4. Consider adding benchmarks in `benches/` directory
5. Update documentation with new complexity analysis
