#pragma once

#include <NimBLEDevice.h>
#include <psa/crypto.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <mutex>
#include <vector>

#include "esphome/components/button/button.h"
#include "esphome/components/event/event.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/automation.h"
#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/core/helpers.h"
#include "esphome/core/preferences.h"

#include "lock_protocol.h"
#include "pairing_ui.h"

// NimBLE's log_common.h defines LOG_LEVEL_* as plain macros, which collide
// with identically-named members of ESPHome enums included downstream.
// ESPHome uses ESPHOME_LOG_LEVEL_* for its own logging, so these undefs are safe.
#undef LOG_LEVEL_NONE
#undef LOG_LEVEL_ERROR
#undef LOG_LEVEL_WARN
#undef LOG_LEVEL_INFO
#undef LOG_LEVEL_DEBUG
#undef LOG_LEVEL_CRITICAL

namespace esphome {
namespace switchbot_keypad_bridge {

// Upper bound (including the trailing NUL) on the persisted keypad name.
constexpr size_t KEYPAD_NAME_MAX = 48;

// UnlockMethod / CommandType / DecodedCommand and the frame decoding live in
// lock_protocol.h — the transport-free half of the protocol.

// ── Concurrency model ───────────────────────────────────────────────────────
// Four execution contexts touch this component. The rule of thumb: only the
// main task acts; every other context hands data over and returns.
//
//   1. ESPHome main task — setup()/loop() and everything they call. The only
//      context that publishes entities, writes NVS, or mutates session and
//      battery-scan state.
//   2. NimBLE host task — server/characteristic callbacks and the battery
//      scan callback. They only enqueue: connect/disconnect/RX frames into
//      rx_queue_, battery adverts into the battery_advert_* fields — both
//      under rx_mutex_, both drained by loop().
//   3. HTTP-server task (pairing wizard) — signals a finished pairing through
//      the pending_keypad_* fields plus the pending_pair_apply_ flag. The
//      fields are written first, then the flag is stored with release
//      semantics; loop() exchanges the flag with acquire before reading them.
//      When adding a pending field, write it BEFORE the flag store.
//   4. Pairing FreeRTOS task ("kp-pair") — owned by KeypadPairer, which
//      exposes progress as Status snapshots copied under its own mutex.
class SwitchbotKeypadBridge : public Component {
  SUB_TEXT_SENSOR(keypad)
  SUB_SENSOR(battery_level)

 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void set_keypad_event(event::Event *ev) { this->keypad_event_ = ev; }
  void set_pairing_ui_html(const uint8_t *html, size_t len) {
    this->pairing_ui_.set_html(html, len);
  }
  void set_battery_scan_interval(uint32_t ms) { this->battery_scan_interval_ms_ = ms; }

  bool is_pairing_active() const { return this->pairing_ui_.is_running(); }

  // Forgets the paired keypad, rotates the shared key in place and
  // re-opens the pairing wizard — no reboot. Invoked by UnpairButton.
  void unpair();

  void add_on_lock_callback(std::function<void()> &&callback) {
    this->on_lock_callbacks_.add(std::move(callback));
  }
  void add_on_unlock_callback(std::function<void(std::string, int)> &&callback) {
    this->on_unlock_callbacks_.add(std::move(callback));
  }
  void add_on_doorbell_callback(std::function<void()> &&callback) {
    this->on_doorbell_callbacks_.add(std::move(callback));
  }

 protected:
  class ServerCallbacks;
  class RxCharCallbacks;
  class BatteryScanCallbacks;
  friend class ServerCallbacks;
  friend class RxCharCallbacks;
  friend class BatteryScanCallbacks;

  enum class LockState : uint8_t {
    LOCKED = 0x81,
    UNLOCKED = 0x91,
  };

  // 4-byte transport header echoed back on every encrypted exchange.
  struct FrameHeader {
    uint8_t key_id;
    uint8_t seq_a;
    uint8_t seq_b;
  };

  // Identity of the paired keypad, persisted to NVS at pairing time so the
  // battery scan can match its advertisement after a reboot. `valid == 0`
  // for keypads paired before this field existed — the scan then learns the
  // MAC from the first recognised keypad advert and persists it.
  struct KeypadInfo {
    uint8_t mac[6]{};   // big-endian, as printed
    uint8_t family{0};  // KeypadFamily
    uint8_t valid{0};
  };

  // ----- Configuration / setup -----------------------------------------------

  // Generates a fresh AES-128 session key into shared_key_ and persists it
  // to NVS — the one place keys are created (first boot and unpair()).
  void create_shared_key_();
  // (Re-)imports shared_key_ into the PSA crypto slot, replacing any handle
  // imported earlier. Lets unpair() re-key the live session without a reboot.
  bool import_aes_key_();

  bool prepare_keys_();
  bool prepare_ble_();

  // ----- BLE write handling --------------------------------------------------

  void on_rx_frame_(const std::string &frame);
  bool is_session_iv_request_(const std::string &frame) const;
  void send_session_iv_();

  void handle_command_(const FrameHeader &header, const DecodedCommand &command);
  void handle_state_poll_(const FrameHeader &header);

  // ----- Transport helpers ---------------------------------------------------

  void send_ack_(const FrameHeader &header);
  void send_encrypted_response_(const FrameHeader &header, const uint8_t *plaintext, size_t length);
  void notify_(const uint8_t *data, size_t length);

  // ----- Crypto (AES-CTR is symmetric, so a single primitive covers both ways) -

  bool aes_ctr_xcrypt_(const uint8_t *input, size_t length, uint8_t *output);
  void rotate_session_iv_();

  // ----- Anti-replay ---------------------------------------------------------

  void reset_session_state_();
  void clear_replay_history_();
  bool is_replayed_ciphertext_(const uint8_t *ciphertext, size_t length) const;
  void record_ciphertext_(const uint8_t *ciphertext, size_t length);

  // ----- Eventing ------------------------------------------------------------

  void publish_lock_();
  void publish_unlock_(UnlockMethod method, int index);
  void publish_doorbell_();

  // ----- Keypad battery (advertisement scan) ----------------------------------

  // The keypad broadcasts its battery level in its BLE advertisement (the
  // command frames it sends us never carry it). A short active scan picks
  // the advert up while the bridge keeps advertising as the lock.
  void maybe_start_battery_scan_();
  void apply_pending_battery_();
  // Runs on the NimBLE host task — parses the advert and queues the result.
  void handle_battery_advert_(const NimBLEAdvertisedDevice *adv);

  // ----- BLE handles ---------------------------------------------------------

  NimBLEServer *server_{nullptr};
  NimBLECharacteristic *tx_characteristic_{nullptr};

  // ----- Thread-safe event queueing from NimBLE callbacks --------------------

  struct QueuedEvent {
    enum Type { CONNECT, DISCONNECT, RX } type;
    std::string frame;
  };

  std::mutex rx_mutex_;
  std::vector<QueuedEvent> rx_queue_;

  void push_connect_();
  void push_disconnect_();
  void push_rx_(const std::string &frame);

  // ----- On-device pairing wizard --------------------------------------------

  PairingUi pairing_ui_{};

  // A finished pairing is signalled from the HTTP-server task; loop() (the
  // main task) consumes it and publishes the keypad name + writes NVS, so
  // neither runs on the network task. pending_keypad_name_ is written
  // before the flag is set — the release/acquire pair makes it safe to
  // read once the flag is observed.
  std::atomic<bool> pending_pair_apply_{false};
  std::string pending_keypad_name_;
  std::string pending_keypad_mac_;
  KeypadFamily pending_keypad_family_{KeypadFamily::ORIGINAL};

  // ----- ESPHome wiring ------------------------------------------------------

  event::Event *keypad_event_{nullptr};
  CallbackManager<void()> on_lock_callbacks_{};
  CallbackManager<void(std::string, int)> on_unlock_callbacks_{};
  CallbackManager<void()> on_doorbell_callbacks_{};

  // ----- User configuration --------------------------------------------------

  // 16-byte AES-128 session key. Generated on first boot, persisted in
  // NVS, rotated by unpair(). Never part of the YAML config.
  std::array<uint8_t, 16> shared_key_{};
  ESPPreferenceObject shared_key_pref_;
  ESPPreferenceObject keypad_name_pref_;
  // Token-slot key_id the keypad uses post-pairing. Auto-learned from the
  // IV-request frame the keypad sends as the first message of every session
  // (Original/Touch=0x88, Vision/Vision Pro=0xC6, …). 0x00 = not yet seen;
  // no encrypted frame is accepted until the IV handshake has set it.
  uint8_t shared_slot_id_{0x00};

  // ----- Runtime state -------------------------------------------------------

  // PSA AES-CTR key handle. Imported once at setup so the per-frame crypto
  // path does not pay the cost (or risk the failure) of re-importing it.
  psa_key_id_t aes_key_handle_{PSA_KEY_ID_NULL};
  LockState lock_state_{LockState::LOCKED};

  // 20-byte session IV response: [0x01, 0x00, 0x00, 0x00, IV(16)].
  // The trailing 16 bytes are also used as the AES-CTR IV for the live session.
  std::array<uint8_t, 20> session_iv_response_{0x01, 0x00, 0x00, 0x00};

  // Per-session anti-replay state. Reset on connect, disconnect, and on
  // every IV re-negotiation.
  static constexpr size_t REPLAY_HISTORY_SIZE = 8;
  static constexpr size_t MAX_REPLAY_PAYLOAD = 32;
  struct ReplayEntry {
    std::array<uint8_t, MAX_REPLAY_PAYLOAD> data{};
    size_t length{0};
  };
  std::array<ReplayEntry, REPLAY_HISTORY_SIZE> replay_history_{};
  size_t replay_head_{0};
  bool iv_established_{false};

  // ----- Keypad battery state --------------------------------------------------

  ESPPreferenceObject keypad_info_pref_;
  KeypadInfo keypad_info_{};
  bool keypad_paired_{false};

  uint32_t battery_scan_interval_ms_{15 * 60 * 1000};
  uint32_t next_battery_scan_at_{0};  // millis() deadline for the next scan
  // Written by loop(), read by the NimBLE scan callback as its "is this our
  // scan window?" gate — hence atomic.
  std::atomic<bool> battery_scan_active_{false};
  BatteryScanCallbacks *battery_scan_callbacks_{nullptr};
  int last_battery_{-1};  // last published value; -1 = nothing published yet

  // Latest advert parsed by the NimBLE scan callback, handed to loop()
  // under rx_mutex_ (same pattern as the RX queue).
  bool battery_advert_pending_{false};
  int battery_advert_value_{-1};
  uint8_t battery_advert_mac_[6]{};
  uint8_t battery_advert_family_{0};
};

// Home Assistant button that unpairs the keypad: forgets it, rotates the
// shared key and re-opens the pairing wizard — all without a reboot.
class UnpairButton : public button::Button, public Parented<SwitchbotKeypadBridge> {
 protected:
  void press_action() override;
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
