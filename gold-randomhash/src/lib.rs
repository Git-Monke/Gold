use ascon_hash::AsconHash;
use belt_hash::BeltHash;
use blake2::Blake2s256;
use fsb::Fsb256;
use gost94::Gost94CryptoPro;
use groestl::Groestl256;
use jh::Jh256;
use ripemd::Ripemd256;
use sha1_checked::Sha1;
use sha2::Sha256;
use sha3::Sha3_256;
use shabal::Shabal256;
use skein::{consts::U32, Skein256};
use sm3::Sm3;
use streebog::Streebog256;
use tiger::Tiger2;
use whirlpool::Whirlpool;

use digest::{Digest, DynDigest};

mod murmur3;
mod transforms;

use murmur3::Checksum;
use rand_mt;

struct RandomHash {
    algs: Vec<Box<dyn DynDigest>>,
}

impl RandomHash {
    pub fn new() -> Self {
        // Algs can continue to grow as long as the provided hash function impleents DynDigest!
        // 18 algorithms is enough for now...
        let algs: Vec<Box<dyn DynDigest>> = vec![
            Box::new(AsconHash::new()),
            Box::new(BeltHash::new()),
            Box::new(Blake2s256::new()),
            Box::new(Fsb256::new()),
            Box::new(Gost94CryptoPro::new()),
            Box::new(Groestl256::new()),
            Box::new(Jh256::new()),
            Box::new(Ripemd256::new()),
            Box::new(Sha1::new()),
            Box::new(Sha256::new()),
            Box::new(Sha3_256::new()),
            Box::new(Shabal256::new()),
            Box::new(Skein256::<U32>::new()),
            Box::new(Sm3::new()),
            Box::new(Streebog256::new()),
            Box::new(Tiger2::new()),
            Box::new(Whirlpool::new()),
        ];

        RandomHash { algs }
    }
}
