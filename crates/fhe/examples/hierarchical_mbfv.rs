use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{distributions::Uniform, prelude::Distribution, thread_rng};
use rayon::prelude::*;
use std::{
    error::Error,
    sync::Arc,
    time::{Duration, Instant},
};

struct Party {
    sk_share: SecretKey,
    pk_share: PublicKeyShare,
}

// This example demonstrates a simple secret ballot system using the combination of
// Fully Homomorphic Encryption (FHE) and threshold cryptography (a multi-party computation).
// Fully Homomorphic Encryption allows us to perform operations on encrypted data, while
// threshold cryptography allows us to distribute the control of a secret key among multiple
// parties, such that the key can only be used when a sufficient number of parties cooperate.
//
// In this example, we'll simulate several parties coordinating to create a shared key,
// then simulate many voters encrypting their vote to that shared key, and use FHE to sum the
// encrypted votes, producing an encrypted tally. The tally is then decrypted using a
// threshold decryption scheme, where each party decrypts the tally to produce a decryption
// share. The decryption shares are then aggregated to produce the plaintext tally.
//
// This implementation is a toy and is not secure for a real election. In a real election,
// the votes would be encrypted independently by each voter and only the ciphertexts would be
// published. The decryption shares would be produced by independent parties and only the
// plaintext tally would be published. This would ensure that no party could determine the
// individual votes or the tally without the cooperation of the other parties.
//
// This example is designed to demonstrate the concepts of FHE and threshold cryptography
// and is not intended to be used in a production environment.

fn main() -> Result<(), Box<dyn Error>> {
    let pb: ProgressBar = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner());
    let main: Instant = Instant::now();

    println!("\n\x1b[1mPractical FHE Workshop: Secret Ballot\x1b[0m");

    // The number of votes that will be cast.
    //
    // Try changing this number to see how the system scales with the number of voters.
    let num_votes: usize = 1000;
    println!("  \x1b[1mVotes:\x1b[0m\t\t{num_votes}");

    // The number of parties that will generate a shared key and decrypt the result.
    //
    // In production, this would be the number of independent entities that need to
    // collaborate to decrypt the result. In this example, we obviously control all
    // of the parties, but we'll still simulate the process.
    //
    // Try changing this number to see how the system scales with the number of parties.
    let num_parties: usize = 9;
    println!("  \x1b[1mParties:\x1b[0m\t\t{num_parties}");

    // Set the parameters for the FHE scheme
    //
    // The degree of the polynomial, usually denoted as `n` in the literature,
    // it determines the size of the ciphertext. A larger degree increases the security,
    // but will also increase the computation and storage.
    let degree: usize = 2048;
    println!("  \x1b[1mDegree:\x1b[0m\t\t{degree}");

    // The plaintext modulus determines the size of the plaintext space. Quite literally, how
    // large the plaintexts you want to represent can be. Plaintexts are typically represented
    // as integers modulo this value. A larger plaintext modulus allows for larger plaintexts.
    // However, larger plaintext modulus also increase noise growth per operation,
    // which can limit the number of computations that can be performed on the ciphertexts.
    // In our case, each vote will be a single bit and we'll sum each vote to produce the tally.
    // The upper bound on the plaintext size is equal to the number of votes cast, so a plaintext
    // modulus of 1032193 is sufficient for a little over 1M votes.
    let plaintext_modulus: u64 = match num_votes {
        1..=999 => 1009,
        1000..=9999 => 10007,
        10000..=99999 => 100003,
        100000..=199999 => 200003,
        200000..=299999 => 300007,
        300000..=399999 => 400009,
        400000..=499999 => 500009,
        500000..=599999 => 600011,
        600000..=699999 => 700001,
        700000..=799999 => 800011,
        800000..=899999 => 900001,
        _ => 1032193,
    };
    println!("  \x1b[1mPlaintext Modulus:\x1b[0m\t{plaintext_modulus}");

    // The moduli are used to control the noise growth in the ciphertexts in a leveled FHE scheme,
    // using a technique called "modulus switching". Each modulus in the vector  is a large prime corresponding
    // to a level in the computation, and computations are performed modulo the current level's modulus.
    // A larger modulus allows for more computations, but also increases the computation and storage costs.
    //
    // Note: In this example, we're using a single modulus, so we're not making use of modulus switching.
    // This is possible because we're only performing addition over the ciphertexts, which leads to little
    // noise growth in the BFV encryption scheme. If our computation was also using multiplication, we would
    // need to use multiple moduli to manage the noise growth.
    let moduli: Vec<u64> = vec![0x3FFFFFFF000001];
    println!("  \x1b[1mModuli:\x1b[0m\t\t{:?}", moduli);

    let params = bfv::BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()
        .unwrap();

    // Generate the Common Random Polynomial (CRP)
    //
    // The CRP is used by each of the party members to generate their public key shares.
    // In this example, we're just grabbing some randomness seeded by the system.
    // In a production environment, we would use some public source of randomness that all
    // of the parties agree on.
    let crp: CommonRandomPoly = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Create the parties and their keys
    //
    // Each party generates a secret key share and a public key share using the CRP.
    let sub_parties: Vec<Party> = (0..num_parties)
        .into_par_iter()
        .map(|_| {
            let sk_share: SecretKey = SecretKey::random(&params, &mut thread_rng());
            let pk_share: PublicKeyShare =
                PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng()).unwrap();
            Party { sk_share, pk_share }
        })
        .collect();

    // Generate three sub-party keys
    //

    let pk_a: PublicKeyShare = (0..num_parties / 3)
        .into_iter()
        .map(|p| sub_parties[p].pk_share.clone())
        .aggregate()?;

    let pk_b: PublicKeyShare = (num_parties / 3..(2 * num_parties) / 3)
        .into_iter()
        .map(|p| sub_parties[p].pk_share.clone())
        .aggregate()?;

    let pk_c: PublicKeyShare = ((2 * num_parties) / 3..num_parties)
        .into_iter()
        .map(|p| sub_parties[p].pk_share.clone())
        .aggregate()?;

    let parties: Vec<PublicKeyShare> = vec![pk_a, pk_b, pk_c];

    // Aggregate the public keys
    //
    // The public keys are aggregated to create a single public key that can be used to encrypt
    // the votes. This is done by summing the public key shares together.
    //
    // Note: because the public key shares are generated using the same CRP, the public key
    // shares are compatible and can be summed together.
    //
    // Note: because the shared public key is the sum of the public key shares, the
    // the public key shares can be aggregated in any order. Meaning the public key shares can
    // be generated asynchronously and aggregated in parallel (although we're not doing that here).
    let pk: PublicKey = parties.iter().map(|p| p.clone()).aggregate()?;

    // Create the plaintext votes
    //
    // Each voter will cast a 1 for yes or a 0 for no. We'll simulate this by generating
    // a random bit for each voter.
    let dist: Uniform<u64> = Uniform::new_inclusive(0, 1);
    let votes: Vec<u64> = (0..num_votes)
        .into_par_iter()
        .map(|_| dist.sample(&mut thread_rng()))
        .collect();

    // Encrypt the votes
    //
    // Each vote is encrypted using the shared public key.
    //
    // Note: In a production environment, the votes would be encrypted independently by each
    // of the voters and only the ciphertexts would be published.
    //
    // Note: encrypting votes is what takes the bulk of the execution time in this example.
    // In a production environment, this cost would be distributed across the voters.
    //
    // Note: votes are encrypted as an array of two integers, where the first column represents
    // the vote against and the second column represents the vote for. This is done to demonstrate
    // the ability to perform arithmetic operations over arrays of integers.
    pb.enable_steady_tick(Duration::from_millis(100));
    let encryption_timer: Instant = Instant::now();
    let results: Vec<_> = votes
        .par_iter()
        .map(|vote| {
            let pt: Plaintext =
                Plaintext::try_encode(&[*vote, 1 - *vote].to_vec(), Encoding::poly(), &params)
                    .unwrap();
            let ct: Ciphertext = pk.try_encrypt(&pt, &mut thread_rng()).unwrap();
            Ok::<fhe::bfv::Ciphertext, std::io::Error>(ct)
        })
        .collect();

    let encrypted_votes: Result<Vec<_>, _> = results.into_iter().collect();
    pb.finish_and_clear();
    println!(
        "  \x1b[1mEncryption Time:\x1b[0m\t{:#?}",
        encryption_timer.elapsed()
    );

    pb.enable_steady_tick(Duration::from_millis(100));
    let tally_timer: Instant = Instant::now();
    // Tally the votes
    //
    // The votes are tallied by summing the encrypted vote ciphertexts together.
    // The result is an encrypted tally of the votes.
    // This is the real magic of homomorphic encryption, we can perform operations on the
    // ciphertexts that correspond to operations on the plaintexts!
    let mut sum: Ciphertext = Ciphertext::zero(&params);
    for vote in encrypted_votes.unwrap().iter() {
        sum += vote;
    }
    let tally: Arc<Ciphertext> = Arc::new(sum);
    pb.finish_and_clear();
    println!(
        "  \x1b[1mTallying time:\x1b[0m\t{:#?}",
        tally_timer.elapsed()
    );

    // Decrypt the tally
    //
    // The tally is decrypted by each of the parties to produce a decryption share.
    // The decryption shares are then aggregated to produce the plaintext tally.
    //
    // Note: As with the public key shares, aggregation of the decryption shares simply involves
    // summing them together. This means the decryption shares can be aggregated in any order
    // and can be generated asynchronously and aggregated in parallel as shares are published.
    pb.enable_steady_tick(Duration::from_millis(100));
    let decryption_timer: Instant = Instant::now();
    let sub_decryption_shares: Result<Vec<DecryptionShare>, std::io::Error> = sub_parties
        .par_iter()
        .map(|party| {
            let sh = DecryptionShare::new(&party.sk_share, &tally, &mut thread_rng()).unwrap();
            Ok::<fhe::mbfv::DecryptionShare, std::io::Error>(sh)
        })
        .collect();

    let sub_decryption_shares = sub_decryption_shares?;

    let mut shares_iter = sub_decryption_shares.into_iter();
    let shares_a: Vec<DecryptionShare> = shares_iter.by_ref().take(num_parties / 3).collect();
    let shares_b: Vec<DecryptionShare> = shares_iter.by_ref().take(num_parties / 3).collect();
    let shares_c: Vec<DecryptionShare> = shares_iter.collect(); // Remaining shares

    let decryption_share_a: DecryptionShare = shares_a.into_iter().aggregate()?;
    let decryption_share_b: DecryptionShare = shares_b.into_iter().aggregate()?;
    let decryption_share_c: DecryptionShare = shares_c.into_iter().aggregate()?;

    let decryption_shares: Vec<DecryptionShare> =
        vec![decryption_share_a, decryption_share_b, decryption_share_c];

    let pt: Plaintext = decryption_shares.into_iter().aggregate()?;

    let tally_vec: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    let tally_result: Vec<u64> = [tally_vec[0], tally_vec[1]].to_vec();
    pb.finish_and_clear();

    println!(
        "  \x1b[1mDecryption time:\x1b[0m\t{:#?}",
        decryption_timer.elapsed()
    );
    println!("  \x1b[1mExecution time:\x1b[0m\t{:#?}", main.elapsed());

    // Print the result
    println!("  \x1b[1mVotes Against:\x1b[0m\t{}", tally_result[0]);
    println!("  \x1b[1mVotes For:\x1b[0m\t\t{}", tally_result[1]);
    pb.finish_and_clear();

    // Check that the results match the expected result
    //
    // Note: this is not possible in production, since we would not know the plaintext inputs.
    let vote_sum: u64 = votes.par_iter().sum();
    let expected_tally: Vec<u64> = [vote_sum as u64, num_votes as u64 - vote_sum].to_vec();
    assert_eq!(tally_result, expected_tally);

    Ok(())
}
