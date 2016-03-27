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
extern crate rustc_serialize;
extern crate serde_json;

use rustc_serialize::hex::ToHex;
use std::cmp::max;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::hash::Hash;
use std::io;
use std::ops::Sub;
use std::marker::PhantomData;
use std::f64::INFINITY;

trait MonoalphabeticCipher {
    fn new(u8) -> Self;
    fn encrypt_byte(&self, u8) -> u8;
    fn decrypt_byte(&self, u8) -> u8;
}

trait SliceCipher {
    fn encrypt_slice(&self, &mut [u8]);
    fn decrypt_slice(&self, &mut [u8]);
}

struct AsciiCaesar(u8);

impl MonoalphabeticCipher for AsciiCaesar {
    fn new(k: u8) -> Self { AsciiCaesar(k) }
    fn encrypt_byte(&self, c: u8) -> u8 {
        match c {
            b'A' ... b'Z' => (((c - b'A') + self.0) % 26) + b'A',
            b'a' ... b'z' => (((c - b'a') + self.0) % 26) + b'a',
            _ => c,
        }
    }
    fn decrypt_byte(&self, c: u8) -> u8 {
        match c {
            b'A' ... b'Z' => (((c - b'A') - self.0) % 26) + b'A',
            b'a' ... b'z' => (((c - b'a') - self.0) % 26) + b'a',
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
                    let mut x = self.grams[i].entry(w).or_insert(0);
                    *x += 1;
                }
            }
        }
        Ok(())
    }
    fn map_kv<K, V, F, G>(&self, f: F, g: G) -> Vec<HashMap<K, V>> where 
            K: Eq + Hash, F: Fn(&[u8]) -> K,
            G: Fn(&HashMap<Vec<u8>, usize>, usize) -> V {
        let mut result = vec![];
        for x in self.grams.iter() {
            let mut tmp = HashMap::new();
            for (k, v) in x { tmp.insert(f(k), g(x, *v)); }
            result.push(tmp);
        }
        result
    }
    fn serialize(&self) -> Vec<HashMap<String, usize>> {
        self.map_kv(|k| k.to_hex(), |_, v| v)
    }
    fn to_distribution(&self) -> Vec<DistributionVector> {
        self.map_kv(|k| k.to_vec(), |hm, v| {
            let total = hm.values().fold(0, |acc, x| acc+x) as f64;
            v as f64 / total
        }).into_iter().map(DistributionVector).collect()
    }
}

fn next_permutation(x: &mut [u8]) -> bool {
    if x.len() == 0 { return false; }
    x[0] += 1;
    //if x[0] == 0 {
    if x[0] == b'z'+1 { x[0] = 0; // hack for AsciiCaesar, at cost of completeness
        return next_permutation(&mut x[1..]);
    }
    true
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
            if !next_permutation(key.as_mut_slice()) { break; }
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
fn solve_vigenere<A: MonoalphabeticCipher>(expected_distribution: DistributionVector, ciphertext: &[u8], keylen: usize) -> Vec<Vec<u8>> {
    let n = expected_distribution.dim();
    //let partial_keys = vec![(vec![0; n], INFINITY); keylen-n];
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
            if !next_permutation(&mut key[i..i+n]) { break; }
        }
        partial_keys.push(best.0.unwrap());
    }
    // TODO: dynamic programming to ensure that ends of keys are consistent, and possibly to use more than 1 size of ngram
    partial_keys
}

fn main() {
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

    let mut vigenere = plaintext.clone();
    VigenereCipher{ key: b"abc".to_vec(), underlying_cipher: PhantomData::<AsciiCaesar> }.encrypt_slice(&mut vigenere);
    println!("{}", std::str::from_utf8(&vigenere).unwrap());

    let mut sherlock_ngrams = NGrams::new();
    let sherlock = File::open("adventures_of_sherlock_holmes.txt").expect("run ./download_corpus.sh to download the corpus");
    sherlock_ngrams.train(2, sherlock).unwrap();
    //let mut sherlock_ngrams_json = File::create("sherlock_ngrams.json").unwrap();
    //serde_json::to_writer(&mut sherlock_ngrams_json, &sherlock_ngrams.serialize()).unwrap();

    let sherlock_distributions = sherlock_ngrams.to_distribution();
    println!("Starting the solver.");
    let tmp = solve_vigenere::<AsciiCaesar>(sherlock_distributions[1].clone(), &vigenere, 3);
    println!("{:?}", tmp);
    /* python samples:
ngrams = [{k.decode('hex'): v for (k, v) in x.items()} for x in eval(open('sherlock_ngrams.json').read())]
by_frequency = lambda d: sorted(d.items(), key=lambda (k,v):v,reverse=True)
by_frequency(ngrams[2])[:10]
    */
}
