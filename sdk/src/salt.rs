// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use rand_chacha::rand_core::{RngCore, SeedableRng};

/// The SaltGenerator trait always the caller to supply
/// a function to generate a salt value used when hashing
/// data.  Providing a unique salt ensures a unique hash for
/// a given data set.
pub trait SaltGenerator {
    /// generate a salt vector
    fn generate_salt(&self) -> Option<Vec<u8>>;
}

/// Default salt generator.
///
/// Behavior depends on how the struct is constructed:
///
/// - `DefaultSalt::default()` — on non-WASM platforms, generates a fresh
///   random 16-byte salt on every call (original behavior).  On WASM,
///   returns `None` so that assertion `HashedUri` hashes are deterministic
///   across signing passes, which is required for the
///   `prepare_identity_assertion` → `finalize_identity_assertion` flow.
///
/// - `DefaultSalt::with_salt(bytes)` — always returns the provided bytes,
///   giving callers full control over the salt on any platform.  Pass an
///   empty `Vec` to explicitly disable salting without relying on the
///   platform default.
pub struct DefaultSalt {
    salt_len: usize,
    /// When `Some`, `generate_salt` returns this value instead of generating
    /// a new random salt.
    fixed_salt: Option<Vec<u8>>,
}

impl DefaultSalt {
    /// Create a `DefaultSalt` that always returns `salt` as the salt value.
    ///
    /// This is useful when you need reproducible assertion hashes or want to
    /// provide a salt derived from external state (e.g. a session key).
    /// Pass an empty `Vec` to disable salting entirely on all platforms.
    pub fn with_salt(salt: Vec<u8>) -> Self {
        DefaultSalt {
            salt_len: salt.len(),
            fixed_salt: Some(salt),
        }
    }

    /// Set the length of the randomly generated salt vector.
    ///
    /// Has no effect when a fixed salt was provided via [`Self::with_salt`].
    #[allow(dead_code)]
    pub fn set_salt_length(&mut self, len: usize) {
        self.salt_len = len;
    }
}

impl Default for DefaultSalt {
    fn default() -> Self {
        DefaultSalt {
            salt_len: 16,
            fixed_salt: None,
        }
    }
}

impl SaltGenerator for DefaultSalt {
    fn generate_salt(&self) -> Option<Vec<u8>> {
        // A caller-supplied salt always wins, on any platform.
        if let Some(ref salt) = self.fixed_salt {
            return if salt.is_empty() { None } else { Some(salt.clone()) };
        }

        // On WASM without a fixed salt, disable random salts so that assertion
        // HashedUri hashes are identical across signing passes.  This is
        // required for the prepare_identity_assertion → finalize_identity_assertion
        // external-signing flow, where the signer_payload CBOR must be
        // byte-for-byte identical between the two passes.
        #[cfg(target_arch = "wasm32")]
        return None;

        // On non-WASM, generate a fresh random salt (original behavior).
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut salt = vec![0u8; self.salt_len];
            let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();
            rng.fill_bytes(&mut salt);
            Some(salt)
        }
    }
}
