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

trait MonoalphabeticCipher {
    fn encrypt_byte(&self, u8) -> u8;
    fn decrypt_byte(&self, u8) -> u8;
}

trait SliceCipher {
    fn encrypt_slice(&self, &mut [u8]);
    fn decrypt_slice(&self, &mut [u8]);
}

struct AsciiCaesar(u8);

impl MonoalphabeticCipher for AsciiCaesar {
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

fn main() {
    let mut tmp = b"Hello, world!".to_owned();
    println!("{}", std::str::from_utf8(&tmp).unwrap());
    PromoteMonoalphabetic(AsciiCaesar(13)).encrypt_slice(&mut tmp);
    println!("{}", std::str::from_utf8(&tmp).unwrap());
}
