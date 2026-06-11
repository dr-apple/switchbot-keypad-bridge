#pragma once

// AES-128-CTR on top of PSA Crypto — the one cipher the SwitchBot keypad
// protocol uses. CTR is symmetric, so a single primitive covers both
// encryption (responses) and decryption (incoming commands).

#include <psa/crypto.h>

#include <cstddef>
#include <cstdint>

namespace esphome {
namespace switchbot_keypad_bridge {

// Run AES-128-CTR over `input` with an already-imported PSA key. `output`
// must hold `length` bytes (in-place operation is not supported by PSA).
// Logs and returns false on failure.
bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length);

// One-shot variant for a raw 16-byte key, imported and destroyed around the
// call — the pairing path, where the keypad's cloud key only lives for the
// duration of a single job.
bool aes_ctr_xcrypt_raw_key(const uint8_t key[16], const uint8_t iv[16],
                            const uint8_t *input, uint8_t *output, size_t length);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
