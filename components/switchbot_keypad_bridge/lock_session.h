#pragma once

// Encrypted-session state machine for the emulated SwitchBot Lock: token-slot
// learning, IV negotiation, frame validation, AES-CTR transport crypto and
// anti-replay. Bytes in, decoded commands out — no NimBLE and no ESPHome
// entities, so the entire validation pipeline lives in one reviewable place.
// The bridge owns the transport (BLE notify) and the business logic (lock
// state, entity publishing) on top of it.

#include <psa/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "lock_protocol.h"

namespace esphome {
namespace switchbot_keypad_bridge {

// 4-byte transport header echoed back on every encrypted exchange.
struct FrameHeader {
  uint8_t key_id;
  uint8_t seq_a;
  uint8_t seq_b;
};

class LockSession {
 public:
  static constexpr size_t HEADER_LEN = 4;   // [0x57|0x01, key_id, seq_a, seq_b]
  static constexpr size_t MAX_PAYLOAD = 32;
  static constexpr size_t MAX_PACKET = HEADER_LEN + MAX_PAYLOAD;

  // Outcome of feeding one received frame into the session.
  enum class Action : uint8_t {
    NONE,     // frame dropped — the reason has been logged
    SEND_IV,  // IV request handled: notify iv_response()
    COMMAND,  // decrypted and decoded: header() / command() are valid
  };

  // (Re-)point the session at an imported PSA AES-CTR key. The bridge owns
  // key generation, NVS persistence and PSA import (including the unpair
  // rotation); the session only uses the handle.
  void set_aes_key(psa_key_id_t key) { this->aes_key_ = key; }

  // Drop all per-connection state: IV, replay history. Called on connect,
  // disconnect and unpair. The learned token slot survives — once adopted
  // from an IV request it is a property of the paired keypad, not of one
  // connection.
  void reset();

  // Forget the learned token slot as well (unpair only).
  void forget_slot() { this->slot_id_ = 0x00; }

  // Validate, decrypt and decode one received frame. On COMMAND the decoded
  // result is available via header()/command() until the next call.
  Action process_frame(const std::string &frame);

  // Valid after process_frame() returned COMMAND.
  const FrameHeader &header() const { return this->header_; }
  const DecodedCommand &command() const { return this->command_; }

  // The 20-byte session-IV response to notify after SEND_IV:
  // [0x01, 0x00, 0x00, 0x00, IV(16)]. The trailing 16 bytes double as the
  // AES-CTR IV of the live session.
  const uint8_t *iv_response() const { return this->iv_response_.data(); }
  size_t iv_response_size() const { return this->iv_response_.size(); }

  // Encrypt `plaintext` into a notify-ready packet
  // [0x01, key_id, seq_a, seq_b, ciphertext…] written to `out` (which must
  // hold MAX_PACKET bytes). Returns the packet length, 0 on failure (logged).
  size_t encrypt_response(const FrameHeader &header, const uint8_t *plaintext,
                          size_t length, uint8_t out[MAX_PACKET]);

 private:
  bool is_iv_request_(const std::string &frame) const;
  void rotate_iv_();

  // AES-CTR is symmetric, so a single primitive covers both directions.
  bool xcrypt_(const uint8_t *input, size_t length, uint8_t *output);

  void clear_replay_history_();
  bool is_replayed_ciphertext_(const uint8_t *ciphertext, size_t length) const;
  void record_ciphertext_(const uint8_t *ciphertext, size_t length);

  psa_key_id_t aes_key_{PSA_KEY_ID_NULL};

  // Token-slot key_id the keypad uses post-pairing. Auto-learned from the
  // IV-request frame the keypad sends as the first message of every session
  // (Original/Touch=0x88, Vision/Vision Pro=0xC6, …). 0x00 = not yet seen;
  // no encrypted frame is accepted until the IV handshake has set it.
  uint8_t slot_id_{0x00};

  std::array<uint8_t, 20> iv_response_{0x01, 0x00, 0x00, 0x00};
  bool iv_established_{false};

  // Per-session anti-replay state. Reset on connect, disconnect, and on
  // every IV re-negotiation.
  static constexpr size_t REPLAY_HISTORY_SIZE = 8;
  struct ReplayEntry {
    std::array<uint8_t, MAX_PAYLOAD> data{};
    size_t length{0};
  };
  std::array<ReplayEntry, REPLAY_HISTORY_SIZE> replay_history_{};
  size_t replay_head_{0};

  FrameHeader header_{};
  DecodedCommand command_{};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
