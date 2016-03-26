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
use std::io;
use std::marker::PhantomData;

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
    fn serialize(&self) -> Vec<HashMap<String, usize>> {
        let mut result = vec![];
        for x in self.grams.iter() {
            let mut tmp = HashMap::new();
            for (k, v) in x { tmp.insert(k.to_hex(), *v); }
            result.push(tmp);
        }
        result
    }
}


fn main() {
    let plaintext = b"Hello, world!".to_vec();
    println!("{}", std::str::from_utf8(&plaintext).unwrap());

    let mut rot13 = plaintext.clone();
    PromoteMonoalphabetic(AsciiCaesar(13)).encrypt_slice(&mut rot13);
    println!("{}", std::str::from_utf8(&rot13).unwrap());

    let mut vigenere = plaintext.clone();
    VigenereCipher{ key: b"abc".to_vec(), underlying_cipher: PhantomData::<AsciiCaesar> }.encrypt_slice(&mut vigenere);
    println!("{}", std::str::from_utf8(&vigenere).unwrap());

    let mut sherlock_ngrams = NGrams::new();
    let sherlock = File::open("adventures_of_sherlock_holmes.txt").expect("run ./download_corpus.sh to download the corpus");
    sherlock_ngrams.train(5, sherlock).unwrap();
    let mut sherlock_ngrams_json = File::create("sherlock_ngrams.json").unwrap();
    serde_json::to_writer(&mut sherlock_ngrams_json, &sherlock_ngrams.serialize()).unwrap();
    /* python samples:
ngrams = [{k.decode('hex'): v for (k, v) in x.items()} for x in eval(open('sherlock_ngrams.json').read())]
by_frequency = lambda d: sorted(d.items(), key=lambda (k,v):v,reverse=True)
by_frequency(ngrams[2])[:10]
    */
}
