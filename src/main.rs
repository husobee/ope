// ope - application that performs ope encryption/decryption
//
extern crate dist_variate;
extern crate rand;
extern crate crypto;

pub mod ope {

    use dist_variate::hgd::{Prng, rhyper, h2pec};
    use std::collections::HashMap;
    use rand::{ThreadRng, Rng};
    use crypto::mac::Mac;
    use crypto::{hmac, aes, mac, sha2};
    use crypto::aes::KeySize;
    use crypto::symmetriccipher::{SynchronousStreamCipher, Encryptor};

    // D and R are sets of consecutive integers
    // HGD takes D, R and y in set R to return x in set D
    // such that for each x* in set D we have x = x* with prob
    // HGD(x-d; |R|, |D|, y-r) where d = min(D) -1, and r = min(R) -1
    //
    //
    // Arrays F and I are empty, and shared state.

    pub struct OPE {
        key: String
    }

    const DOMAIN: u64 = u16::max_value() as u64 -1;
    const RANGE: u64 = u32::max_value() as u64 -1;

    impl OPE {
        pub fn new(key: String) -> OPE {
            OPE{
                key: key,
            }
        }

        pub fn encrypt(&mut self, plaintext: u32) -> u64 {
            // perform OPE encryption
            self.lazy_sample((1, DOMAIN), (1, RANGE), plaintext as u64)
        }


        pub fn decrypt(ciphertext: u32) -> u64 {
            // perform OPE decryption
            42
        }

        pub fn tape_gen(&mut self, input: u64) -> Box<SynchronousStreamCipher + 'static> {
            // perform hmac sha256 of the input to derive the key
            //
            let s = input.to_string();
            let mut hmac = hmac::Hmac::new(sha2::Sha256::new(), self.key.as_bytes());

            hmac.input(s.as_bytes());
            let result = hmac.result();

            // encrypt with aes ctr to generate random u32
            aes::ctr(KeySize::KeySize256, result.code(), &[0;16])
        }

        // lazy_sample - take in the Domain, Range and m input domain point
        pub fn lazy_sample(&mut self, D: (u64, u64), R: (u64, u64), m: u64) -> u64 {

            // setup variables
            // D and R tuples have range min in 0 and max in 1 positions
            let M = D.1 - D.0 + 1;
            let N = R.1 - R.0 + 1;

            let d = D.0 -1;
            let r = R.0 -1;

            let rgap = (N as f64/2.0).ceil() as u64;
            let y = r + rgap;

            assert!(M <= N, "domain needs to be less than range");


            if M == 1 {
                let mut prng = Prng::new(self.tape_gen(m));

                let mut output = vec![0;16];
                prng.cipher.process(&[0;16], &mut output);

                let s: u64 = (output[0] as u64) << 56 |
                    (output[1] as u64) << 48 | (output[2] as u64) << 40 |
                    (output[3] as u64) << 32 |
                    (output[4] as u64) << 24 |
                    (output[5] as u64) << 16 | (output[6] as u64) << 8 |
                    (output[7] as u64);

                r + s % N
            } else {
                let mut prng = Prng::new(self.tape_gen(y));
                let x = h2pec(rgap, M, N-M, &mut prng);

                if m <= x {
                    self.lazy_sample((d+1, d+x-1), (r+1, y-1), m)
                } else {
                    self.lazy_sample((d+x, d+M), (y, r+N), m)
                }
            }
        }

    }
}

fn main() {

    // pass OPE the key
    let mut ope = ope::OPE::new(String::from("my secret key"));

    let a = ope.encrypt(1529939373);
    let b = ope.encrypt(1529939377);
    let c = ope.encrypt(1529939378);

    println!("a: {}, b: {}, c: {}", a, b, c);
    assert!(a < b);
    assert!(b < c);

}
