use std::sync::Arc;

use fhe::bfv::Ciphertext;
use fhe::trbfv::{AggregatedKeyShare, OneTimeNoiseShare, SessionId, ShareManager};
use fhe_math::rq::Ntt;

fn clone_noise(
    manager: ShareManager,
    ciphertext: Arc<Ciphertext>,
    key: AggregatedKeyShare<Ntt>,
    noise: OneTimeNoiseShare,
    use_session: SessionId,
) {
    let _ = manager.decryption_share(
        ciphertext.clone(),
        1,
        key.clone(),
        use_session,
        noise.clone(),
    );
    let _ = manager.decryption_share(ciphertext, 2, key, use_session, noise);
}

fn main() {}
