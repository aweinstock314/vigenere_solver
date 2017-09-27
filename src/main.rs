/*
Copyright 2016 Avi Weinstock

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
extern crate argparse;
extern crate serde;
extern crate rustc_hex;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

use argparse::{ArgumentParser, Store};
use rustc_hex::{FromHex, ToHex};
use serde::Deserialize;
use std::cmp::max;
use std::collections::HashMap;
use std::env::args;
use std::error::Error;
use std::f64::INFINITY;
use std::fs::File;
use std::hash::Hash;
use std::io;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::ops::{Range, Sub};
use std::process::exit;

trait MonoalphabeticCipher {
    fn new(u8) -> Self;
    fn active_keyspace() -> Range<u8>;
    fn encrypt_byte(&self, u8) -> u8;
    fn decrypt_byte(&self, u8) -> u8;
}

trait SliceCipher {
    fn encrypt_slice(&self, &mut [u8]);
    fn decrypt_slice(&self, &mut [u8]);
}

struct AsciiCaesar(u8);

impl MonoalphabeticCipher for AsciiCaesar {
    fn new(k: u8) -> Self { AsciiCaesar(k % 26) }
    fn active_keyspace() -> Range<u8> { 0..25 }
    fn encrypt_byte(&self, c: u8) -> u8 {
        match c {
            b'A' ... b'Z' => (((c - b'A') + 26 + self.0) % 26) + b'A',
            b'a' ... b'z' => (((c - b'a') + 26 + self.0) % 26) + b'a',
            _ => c,
        }
    }
    fn decrypt_byte(&self, c: u8) -> u8 {
        match c {
            b'A' ... b'Z' => (((c - b'A') + 26 - self.0) % 26) + b'A',
            b'a' ... b'z' => (((c - b'a') + 26 - self.0) % 26) + b'a',
            _ => c,
        }
    }
}

struct PromoteMonoalphabetic<A>(A);

impl<A: MonoalphabeticCipher> SliceCipher for PromoteMonoalphabetic<A> {
    fn encrypt_slice(&self, s: &mut [u8]) {
        for c in s.iter_mut() { *c = self.0.encrypt_byte(*c); }
    }
    fn decrypt_slice(&self, s: &mut [u8]) {
        for c in s.iter_mut() { *c = self.0.decrypt_byte(*c); }
    }
}

struct VigenereCipher<A> {
    key: Vec<u8>,
    underlying_cipher: PhantomData<A>,
}

impl<A: MonoalphabeticCipher> SliceCipher for VigenereCipher<A> {
    fn encrypt_slice(&self, s: &mut [u8]) {
        for (i, c) in s.iter_mut().enumerate() {
            *c = A::new(self.key[i % self.key.len()]).encrypt_byte(*c);
        }
    }
    fn decrypt_slice(&self, s: &mut [u8]) {
        for (i, c) in s.iter_mut().enumerate() {
            *c = A::new(self.key[i % self.key.len()]).decrypt_byte(*c);
        }
    }
}

struct NGrams {
    grams: Vec<HashMap<Vec<u8>, usize>>,
}

impl NGrams {
    fn new() -> Self { NGrams{ grams: vec!() } }
    fn train<R: io::Read>(&mut self, n: usize, corpus: R) -> Result<(), Box<Error>> {
        fn push(window: &mut Vec<Option<u8>>, new_byte: u8) {
            let mut w_iter = window.iter_mut().peekable();
            loop {
                let x = match w_iter.next() {
                    Some(x) => x,
                    None => break,
                };
                *x = match w_iter.peek() {
                    Some(next_byte) => **next_byte,
                    None => Some(new_byte),
                };
            }
        }
        // sequence :: (Monad m, Traversable t) => t (m a) -> m (t a)
        // m ~ Option, t ~ Vec/slice, a ~ u8
        fn sequence(v: &[Option<u8>]) -> Option<Vec<u8>> {
            let mut tmp = vec![];
            for x in v.iter() {
                match *x {
                    Some(x) => tmp.push(x),
                    None => return None,
                }
            }
            Some(tmp)
        }
        { let m = self.grams.len(); self.grams.resize(max(n, m), HashMap::new()); }
        let mut windows: Vec<Vec<Option<u8>>> = vec![];
        for i in 0..n { windows.push(vec![None; i+1]); }
        for c in corpus.bytes() {
            let c = try!(c);
            for (i, window) in windows.iter_mut().enumerate() {
                push(window, c);
                if let Some(w) = sequence(window) {
                    let x = self.grams[i].entry(w).or_insert(0);
                    *x += 1;
                }
            }
        }
        Ok(())
    }
    fn serialize(&self) -> Vec<HashMap<String, usize>> {
        map_kv(&self.grams, |k| k.to_hex(), |_, &v| v)
    }
    fn deserialize(ngrams: &Vec<HashMap<String, usize>>) -> Self {
        let h = map_kv(ngrams, |k| k.from_hex().expect("key was not valid hex"), |_, &v| v);
        NGrams { grams : h }
    }
    fn to_distribution(&self) -> Vec<DistributionVector> {
        map_kv(&self.grams, |k| k.to_vec(), |hm, &v| {
            let total = hm.values().fold(0, |acc, x| acc+x) as f64;
            v as f64 / total
        }).into_iter().map(DistributionVector).collect()
    }
}

fn map_kv<K1, V1, K2, V2, F, G>(h: &Vec<HashMap<K1, V1>>, f: F, g: G) -> Vec<HashMap<K2, V2>> where 
        K1: Eq + Hash, K2: Eq+Hash,
        F: Fn(&K1) -> K2,
        G: Fn(&HashMap<K1, V1>, &V1) -> V2 {
    let mut result = vec![];
    for x in h.iter() {
        let mut tmp = HashMap::new();
        for (k, v) in x { tmp.insert(f(k), g(x, v)); }
        result.push(tmp);
    }
    result
}

fn next_permutation(x: &mut [u8], r: Range<u8>) -> bool {
    if x.len() == 0 { return false; }
    if x[0].wrapping_add(1) == r.end.wrapping_add(1) {
        x[0] = r.start;
        next_permutation(&mut x[1..], r)
    }
    else {
        x[0] = x[0].wrapping_add(1);
        true
    }
}

#[derive(Clone)]
struct DistributionVector(HashMap<Vec<u8>, f64>);

impl DistributionVector {
    fn from_occurrences(x: HashMap<Vec<u8>, usize>) -> Self {
        let total = x.values().fold(0, |acc, x| acc+x) as f64;
        let mut result = DistributionVector(HashMap::new());
        for (k, v) in x.into_iter() {
            result.0.insert(k, v as f64 / total);
        }
        result
    }
    // this assumes all keys are the same length, not sure if rust has enough dependent types to do better
    fn dim(&self) -> usize {
        match self.0.keys().next() {
            Some(k) => k.len(),
            None => 0,
        }
    }
    fn norm(&self) -> f64 {
        let size = match self.dim() {
            0 => return 0.0,
            n => n,
        };
        let mut key = vec![0; size];
        let mut result = 0f64;
        loop {
            result += (*self.0.get(&key).unwrap_or(&0.0)).powi(2);
            if !next_permutation(key.as_mut_slice(), 0..255) { break; }
        }
        result.sqrt()
    }
}

impl<'a> Sub<&'a DistributionVector> for DistributionVector {
    type Output = DistributionVector;
    fn sub(self, rhs: &DistributionVector) -> Self::Output {
        let mut result = HashMap::new();
        for (k, v) in self.0.iter() {
            *result.entry(k.clone()).or_insert(*v) -= *rhs.0.get(k).unwrap_or(&0.0);
        }
        for (k, v) in rhs.0.iter() {
            // if the lhs didn't have it, subtract it from 0
            if !result.contains_key(k) {
                result.insert(k.clone(), -*v);
            }
        }
        DistributionVector(result)
    }
}

// expected_ngrams == plaintext distribution
// keylen == vigenere key length
// n = which size ngram to use
//fn solve_vigenere<A: MonoalphabeticCipher>(expected_ngrams: NGrams, ciphertext: &[u8], keylen: usize, n: usize) {
fn solve_vigenere<A: MonoalphabeticCipher>(expected_distribution: DistributionVector, ciphertext: &[u8], keylen: usize) -> Vec<u8> {
    let n = expected_distribution.dim();
    let mut partial_keys: Vec<Vec<u8>> = vec![];
    for i in 0..(keylen-n+1) {
        let mut key = vec![0u8; keylen];
        println!("{}, {:?}", i, key);
        let mut best = (None, INFINITY);
        loop {
            let mut ctxt = ciphertext.to_vec();
            VigenereCipher { key: key.clone(), underlying_cipher: PhantomData::<A> }.decrypt_slice(&mut ctxt);
            let mut occurrences = HashMap::new();
            for chunk in ctxt.chunks(keylen) {
                if chunk.len() >= i+n {
                    //println!("{:?}", chunk);
                    //println!("\t{:?}", &chunk[i..i+n]);
                    *occurrences.entry(chunk[i..i+n].to_vec()).or_insert(0) += 1;
                }
            }
            let current_distance = (DistributionVector::from_occurrences(occurrences) - &expected_distribution).norm();
            if current_distance < best.1 {
                best.0 = Some(key[i..i+n].to_vec());
                best.1 = current_distance;
            }
            println!("best: {:?}; current: {:?}, {}", best, &key, current_distance);
            if !next_permutation(&mut key[i..i+n], A::active_keyspace()) { break; }
        }
        partial_keys.push(best.0.unwrap());
    }
    // TODO: dynamic programming to ensure that ends of keys are consistent, and possibly to use more than 1 size of ngram
    let mut key = vec![];
    let mut partial_key_iter = partial_keys.iter().peekable();
    while let Some(partial_key) = partial_key_iter.next() {
        key.push(partial_key[0]);
        if n > 1 {
            if let None = partial_key_iter.peek() {
                // last element, deal with overlap
                key.push(partial_key[n-1]);
            }
        }
    }
    key
}

enum CryptionDirection { Encrypt, Decrypt }

#[derive(Serialize, Deserialize, Debug)]
enum Action {
    CalculateNGrams,
    Encrypt,
    Decrypt,
    Solve
}

impl std::str::FromStr for Action {
    type Err = serde_json::error::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

fn main() {
    let argv: Vec<String> = args().collect();
    /*let mut action: Action = Action::CalculateNGrams;
    {
        let mut ap = ArgumentParser::new();
        ap.refer(&mut action).add_argument("action", Store, "Which subprogram to run");
        ap.parse_args_or_exit();
    }
    exit(1);*/
    fn usage() -> ! {
        println!("Usage: vigenere_solver SUBPROGRAM [ARGS...]");
        println!("\tngrams n corpus.txt ngrams.json");
        println!("\t{{en,de}}crypt [asciicaesar, vigenere] key input.ptxt output.ctxt");
        println!("\tsolve_vigenere [asciicaesar] ngrams.json keylength ngramlength input.ptxt output.ctxt");
        exit(1);
    }
    if argv.len() < 2 { usage(); }
    match argv[1].as_str() {
        "ngrams" => {
            if argv.len() < 5 { usage(); }
            ngrams_main(&argv[2], &argv[3], &argv[4]);
        },
        "encrypt" => {
            if argv.len() < 6 { usage(); }
            crypt_main(CryptionDirection::Encrypt, &argv[2], &argv[3], &argv[4], &argv[5]);
        },
        "decrypt" => {
            if argv.len() < 6 { usage(); }
            crypt_main(CryptionDirection::Decrypt, &argv[2], &argv[3], &argv[4], &argv[5]);
        },
        "solve_vigenere" => {
            if argv.len() < 8 { usage(); }
            solver_main(&argv[2], &argv[3], &argv[4], &argv[5], &argv[6], &argv[7]);
        },
        other => println!("Unrecognized subprogram \"{}\". Options: ngrams, encrypt, decrypt, solve_vigenere", other),
    }
}

fn ngrams_main(n: &str, input: &str, output: &str) {
    let n = usize::from_str_radix(n, 10).expect("couldn't parse n");
    let mut ngrams = NGrams::new();
    let corpus = File::open(input).expect("error opening the input for ngrams_main");
    ngrams.train(n, corpus).expect("error calculating the ngrams model");
    let mut ngrams_json = File::create(output).expect("error creating the output file");
    serde_json::to_writer(&mut ngrams_json, &ngrams.serialize()).expect("error writing the json to the output file");

}

fn crypt_main(dir: CryptionDirection, cipher: &str, key: &str, input: &str, output: &str) {
    let c: Box<SliceCipher> = match cipher {
        "asciicaesar" => Box::new(PromoteMonoalphabetic(AsciiCaesar::new(u8::from_str_radix(key,10).expect("error parsing key for crypt_main")))),
        "vigenere" => Box::new(VigenereCipher { key: key.as_bytes().to_vec(), underlying_cipher: PhantomData::<AsciiCaesar> }), // TODO: more generic
        _ => return,
    };
    let mut i = File::open(input).expect("error opening the input for crypt_main");
    let mut o = File::create(output).expect("error opening the output for crypt_main");
    let mut tmp = vec![];
    i.read_to_end(&mut tmp).expect("error reading the input for crypt_main");
    match dir {
        CryptionDirection::Encrypt => c.encrypt_slice(&mut tmp),
        CryptionDirection::Decrypt => c.decrypt_slice(&mut tmp),
    }
    o.write_all(&tmp).expect("error writing the output for crypt_main");
}

fn solver_main(cipher: &str, ngrams: &str, keylength: &str, ngramlength: &str, input: &str, output: &str) {
    // TODO: needs ngrams deserializer
    unimplemented!();
}


fn old_main() {
    // TODO: multipart command-line tool based on argv ({en,de}crypt, ngrams calculation)
    //let plaintext = b"Hello, world!".to_vec();
    let plaintext = b"His manner was not effusive. It seldom was; but he was glad, I think,
to see me. With hardly a word spoken, but with a kindly eye, he waved
me to an arm-chair, threw across his case of cigars, and indicated a
spirit case and a gasogene in the corner. Then he stood before the
fire, and looked me over in his singular introspective fashion.
".to_vec();
    println!("{}", std::str::from_utf8(&plaintext).unwrap());

    let mut rot13 = plaintext.clone();
    PromoteMonoalphabetic(AsciiCaesar(13)).encrypt_slice(&mut rot13);
    println!("{}", std::str::from_utf8(&rot13).unwrap());

    let key = b"abcdefgh";
    let mut vigenere = plaintext.clone();
    VigenereCipher{ key: key.to_vec(), underlying_cipher: PhantomData::<AsciiCaesar> }.encrypt_slice(&mut vigenere);
    println!("{}", std::str::from_utf8(&vigenere).unwrap());

    let mut sherlock_ngrams = NGrams::new();
    let sherlock = File::open("adventures_of_sherlock_holmes.txt").expect("run ./download_corpus.sh to download the corpus");
    sherlock_ngrams.train(2, sherlock).unwrap();
    let mut sherlock_ngrams_json = File::create("sherlock_ngrams.json").unwrap();
    serde_json::to_writer(&mut sherlock_ngrams_json, &sherlock_ngrams.serialize()).unwrap();

    let sherlock_distributions = sherlock_ngrams.to_distribution();
    println!("Starting the solver.");
    let key2 = solve_vigenere::<AsciiCaesar>(sherlock_distributions[1].clone(), &vigenere, key.len());
    println!("{:?}", key2);
    let mut vigenere2 = vigenere.clone();
    VigenereCipher{ key: key2, underlying_cipher: PhantomData::<AsciiCaesar> }.decrypt_slice(&mut vigenere2);
    println!("{}", std::str::from_utf8(&vigenere2).unwrap());

    /* python samples:
ngrams = [{k.decode('hex'): v for (k, v) in x.items()} for x in eval(open('sherlock_ngrams.json').read())]
by_frequency = lambda d: sorted(d.items(), key=lambda (k,v):v,reverse=True)
by_frequency(ngrams[2])[:10]
    */
}
