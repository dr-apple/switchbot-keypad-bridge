#include "switchbot_keypad_bridge.h"

#include <cstdio>
#include <cstring>

#include <esp_mac.h>
#include <esp_random.h>
#include <psa/crypto.h>

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge";

// BLE service / characteristic UUIDs as exposed by a real SwitchBot Lock.
constexpr const char *SERVICE_UUID = "cba20d00-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *RX_CHAR_UUID = "cba20002-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *TX_CHAR_UUID = "cba20003-224d-11e6-9fb8-0002a5d5c51b";

// SwitchBot's OUI. Applied to the chip's factory MAC at boot so the bridge
// advertises within SwitchBot's address range — the Keypad Vision filters
// scan results on this prefix.
constexpr uint8_t SPOOFED_OUI[3] = {0xB0, 0xE9, 0xFE};

// Manufacturer-specific advertising blob published by the genuine lock.
constexpr uint8_t ADVERTISING_MFG_DATA[] = {0x27, 0x09, 0x00, 0x10,
                                            0xA5, 0xB8, 0x00, 0x00, 0x00};

// Plain-text command frames as decoded from the keypad. The state-poll
// constant is a 3-byte prefix because the trailing byte is a per-family
// model suffix (varies between keypad models).
constexpr uint8_t FRAME_LOCK[8]              = {0x0F, 0x4E, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t FRAME_ACTION[4]            = {0x0F, 0x4E, 0x01, 0x03};
constexpr uint8_t FRAME_STATE_POLL_PREFIX[3] = {0x0F, 0x4F, 0x81};
// Doorbell press (Keypad Vision). A short, distinct 2-byte opcode the keypad
// sends on the shared slot when its doorbell button is pressed.
constexpr uint8_t FRAME_DOORBELL[2]          = {0x01, 0x03};

// Encrypted response payloads sent back to the keypad on lock/unlock.
constexpr uint8_t RESPONSE_LOCK[5]   = {0x90, 0x0A, 0x7F, 0x7F, 0x00};
constexpr uint8_t RESPONSE_UNLOCK[5] = {0x98, 0x08, 0x7F, 0x7F, 0x00};

// Trailing 13 bytes appended to the lock-state byte when answering a state poll.
constexpr uint8_t STATE_PAYLOAD_TAIL[13] = {0x08, 0x08, 0x41, 0x00, 0x00, 0x00, 0x00,
                                            0x80, 0xF2, 0xFB, 0x00, 0x00, 0x00};

// Encrypted protocol framing.
constexpr uint8_t  PROTOCOL_MAGIC      = 0x57;
constexpr size_t   ENCRYPTED_HEADER    = 4;     // [0x57, key_id, seq_a, seq_b]
constexpr size_t   MAX_PAYLOAD_LEN     = 32;

// Session IV negotiation: first frame received after connect.
// Shape: 57 00 00 00 0F 21 03 <key_id>
constexpr size_t   SESSION_IV_REQ_MIN  = 8;

// Unlock frame layout: [hdr(4) | method | marker(0x80) | index | ...]
constexpr size_t   UNLOCK_METHOD_OFFSET = 4;
constexpr size_t   UNLOCK_MARKER_OFFSET = 5;
constexpr size_t   UNLOCK_INDEX_OFFSET  = 6;
constexpr uint8_t  UNLOCK_MARKER        = 0x80;
constexpr uint8_t  UNLOCK_INDEX_BASE    = 0x0A;

constexpr size_t   AES_KEY_SIZE   = 16;
constexpr size_t   AES_IV_SIZE    = 16;
constexpr size_t   IV_RESPONSE_HEADER = 4;  // session_iv_response_ prefix before the IV bytes

}  // namespace

const char *unlock_method_name(UnlockMethod method) {
  switch (method) {
    case UnlockMethod::FINGERPRINT:
      return "fingerprint";
    case UnlockMethod::PIN:
      return "pin";
    case UnlockMethod::NFC:
      return "nfc";
    case UnlockMethod::FACE:
      return "face";
    default:
      return "unknown";
  }
}

// ---------------------------------------------------------------------------
// NimBLE callback bridges
// ---------------------------------------------------------------------------

class SwitchbotKeypadBridge::ServerCallbacks : public NimBLEServerCallbacks {
 public:
  explicit ServerCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onConnect(NimBLEServer *server, NimBLEConnInfo &info) override {
    this->parent_->push_connect_();
  }

  void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override {
    this->parent_->push_disconnect_();
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::RxCharCallbacks : public NimBLECharacteristicCallbacks {
 public:
  explicit RxCharCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onWrite(NimBLECharacteristic *characteristic, NimBLEConnInfo &info) override {
    const std::string value = characteristic->getValue();
    if (value.empty())
      return;
    this->parent_->push_rx_(value);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

// ---------------------------------------------------------------------------
// Thread-safe event queueing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::push_connect_() {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::CONNECT, ""});
}

void SwitchbotKeypadBridge::push_disconnect_() {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::DISCONNECT, ""});
}

void SwitchbotKeypadBridge::push_rx_(const std::string &frame) {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::RX, frame});
}

// ---------------------------------------------------------------------------
// Component lifecycle
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::setup() {
  // Load — or, on first boot, generate — the 16-byte AES-128 session key.
  // unpair() rotates it; it is never part of the YAML config.
  this->shared_key_pref_ =
      global_preferences->make_preference<std::array<uint8_t, 16>>(0x534B4559UL /* 'SKEY' */);
  if (!this->shared_key_pref_.load(&this->shared_key_)) {
    this->create_shared_key_();
    ESP_LOGI(TAG, "Generated a fresh shared key");
  }

  // Restore the paired keypad name (if any) and publish it to the sensor.
  this->keypad_name_pref_ = global_preferences->make_preference<char[KEYPAD_NAME_MAX]>(
      0x534B5042UL /* 'SKPB' */);
  char stored_name[KEYPAD_NAME_MAX] = {};
  bool have_keypad = false;
  if (this->keypad_name_pref_.load(&stored_name) && stored_name[0] != '\0') {
    stored_name[KEYPAD_NAME_MAX - 1] = '\0';
    have_keypad = true;
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state(stored_name);
    }
    ESP_LOGI(TAG, "Paired keypad: '%s'", stored_name);
  } else {
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state("Unpaired");
    }
  }

  if (!this->prepare_keys_() || !this->prepare_ble_()) {
    this->mark_failed();
    return;
  }
  ESP_LOGI(TAG, "Ready. Advertising on %s",
           NimBLEDevice::getAddress().toString().c_str());

  this->pairing_ui_.set_shared_key(this->shared_key_);
  this->pairing_ui_.set_on_paired_callback([this](const std::string &name) {
    // Runs on the HTTP-server task — keep it minimal: stash the name and
    // raise a flag. loop() (the main task) publishes the text sensor,
    // writes NVS and stops the server.
    this->pending_keypad_name_ = name;
    this->pending_pair_apply_.store(true, std::memory_order_release);
  });
  // Pairing mode: with no keypad paired yet, open the wizard right away
  // so the very first pairing needs no button press.
  if (!have_keypad) {
    if (this->pairing_ui_.start()) {
      ESP_LOGI(TAG, "No keypad paired — starting pairing mode");
    } else {
      ESP_LOGW(TAG, "Pairing UI failed to start; check port 80 is free");
    }
  }
}

void SwitchbotKeypadBridge::loop() {
  // Apply a pairing that completed on the HTTP-server task. The text-sensor
  // publish and the NVS write run here, on the main task.
  if (this->pending_pair_apply_.exchange(false, std::memory_order_acquire)) {
    const std::string &name = this->pending_keypad_name_;

    // Persist the name so it survives a reboot and can be re-published.
    char buf[KEYPAD_NAME_MAX] = {};
    name.copy(buf, sizeof(buf) - 1);
    const bool saved = this->keypad_name_pref_.save(&buf);
    global_preferences->sync();

    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state(name);
    }
    ESP_LOGI(TAG, "Paired keypad: '%s' (nvs save %s)", name.c_str(),
             saved ? "ok" : "FAILED");

    // Pairing done — close the wizard server. Defer ~2 s so the wizard's
    // final status poll still gets its reply. set_timeout() is safe here:
    // loop() runs on the main task.
    this->set_timeout(2000, [this]() {
      this->pairing_ui_.stop();
      ESP_LOGI(TAG, "Pairing UI stopped");
    });
  }

  // Drain the RX queue. Doing a copy and clear limits memory allocation
  // in the NimBLE thread side to the bare minimum, avoiding heap thrashing.
  std::vector<QueuedEvent> pending;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    if (!this->rx_queue_.empty()) {
      pending = this->rx_queue_;
      this->rx_queue_.clear();
    }
  }

  for (const auto &ev : pending) {
    if (ev.type == QueuedEvent::CONNECT) {
      ESP_LOGI(TAG, "Keypad connected");
      this->reset_session_state_();
    } else if (ev.type == QueuedEvent::DISCONNECT) {
      ESP_LOGI(TAG, "Keypad disconnected, restarting advertising");
      this->reset_session_state_();
      NimBLEDevice::startAdvertising();
    } else if (ev.type == QueuedEvent::RX) {
      this->on_rx_frame_(ev.frame);
    }
  }
}

void SwitchbotKeypadBridge::unpair() {
  ESP_LOGI(TAG, "Unpairing — rotating the shared key and re-opening the pairing wizard");

  // Rotate the key and swap it into the live crypto slot: the previously
  // paired keypad can no longer command the bridge, with no reboot needed.
  this->create_shared_key_();
  if (!this->import_aes_key_()) {
    ESP_LOGE(TAG, "Key rotation failed — unpair aborted");
    return;
  }

  // Forget the paired keypad name.
  char empty[KEYPAD_NAME_MAX] = {};
  this->keypad_name_pref_.save(&empty);
  global_preferences->sync();
  if (this->keypad_text_sensor_ != nullptr) {
    this->keypad_text_sensor_->publish_state("Unpaired");
  }

  // Invalidate any in-flight BLE session — it is keyed to the old secret.
  this->reset_session_state_();
  this->shared_slot_id_ = 0x00;

  // Re-enter pairing mode straight away with the rotated key.
  this->pairing_ui_.set_shared_key(this->shared_key_);
  if (this->pairing_ui_.start()) {
    ESP_LOGI(TAG, "Unpaired — re-entering pairing mode");
  } else {
    ESP_LOGW(TAG, "Pairing UI failed to start; check port 80 is free");
  }
}

void UnpairButton::press_action() {
  if (this->parent_->is_pairing_active()) {
    ESP_LOGW(TAG, "Pairing is already active, ignoring Unpair action");
    return;
  }
  this->parent_->unpair();
}

void SwitchbotKeypadBridge::dump_config() {
  ESP_LOGCONFIG(TAG, "SwitchBot Keypad Bridge:");
  ESP_LOGCONFIG(TAG, "  BLE address: %s", NimBLEDevice::getAddress().toString().c_str());
  ESP_LOGCONFIG(TAG, "  Pairing UI: port 80");
  if (this->is_failed()) {
    ESP_LOGE(TAG, "  Initialization failed - see previous errors");
  }
}

void SwitchbotKeypadBridge::create_shared_key_() {
  esp_fill_random(this->shared_key_.data(), this->shared_key_.size());
  this->shared_key_pref_.save(&this->shared_key_);
  global_preferences->sync();
}

bool SwitchbotKeypadBridge::import_aes_key_() {
  // Drop any previously imported handle so the slot can be re-keyed in
  // place — unpair() rotates the key without rebooting.
  if (this->aes_key_handle_ != PSA_KEY_ID_NULL) {
    psa_destroy_key(this->aes_key_handle_);
    this->aes_key_handle_ = PSA_KEY_ID_NULL;
  }

  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);
  psa_status_t status = psa_import_key(&attrs, this->shared_key_.data(), AES_KEY_SIZE,
                                       &this->aes_key_handle_);
  psa_reset_key_attributes(&attrs);

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }
  return true;
}

bool SwitchbotKeypadBridge::prepare_keys_() {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "PSA Crypto init failed (%d)", static_cast<int>(status));
    return false;
  }
  return this->import_aes_key_();
}

bool SwitchbotKeypadBridge::prepare_ble_() {
  // Spoof a SwitchBot-OUI BLE address: keep the chip-unique tail, replace
  // the leading three bytes. The Vision keypad filters scan results on this
  // prefix and would otherwise ignore the bridge. Must run before NimBLE
  // init so the controller picks up the patched base MAC.
  uint8_t base[6];
  esp_err_t err = esp_efuse_mac_get_default(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_efuse_mac_get_default failed (err=0x%X)", err);
    return false;
  }
  std::memcpy(base, SPOOFED_OUI, sizeof(SPOOFED_OUI));
  err = esp_base_mac_addr_set(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_base_mac_addr_set failed (err=0x%X)", err);
    return false;
  }
  ESP_LOGD(TAG, "Base MAC set to %02X:%02X:%02X:%02X:%02X:%02X (SwitchBot OUI spoof)",
           base[0], base[1], base[2], base[3], base[4], base[5]);

  NimBLEDevice::init("WoLock");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  this->server_ = NimBLEDevice::createServer();
  this->server_->setCallbacks(new ServerCallbacks(this));

  NimBLEService *service = this->server_->createService(SERVICE_UUID);
  this->tx_characteristic_ = service->createCharacteristic(TX_CHAR_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic *rx = service->createCharacteristic(
      RX_CHAR_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCharCallbacks(this));

  NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
  advertising->addServiceUUID(service->getUUID());
  advertising->setManufacturerData(
      std::string(reinterpret_cast<const char *>(ADVERTISING_MFG_DATA), sizeof(ADVERTISING_MFG_DATA)));
  advertising->start();
  return true;
}

// ---------------------------------------------------------------------------
// RX path
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::on_rx_frame_(const std::string &frame) {
  ESP_LOGV(TAG, "RX WIRE %zu bytes: %s", frame.size(),
           format_hex_pretty(reinterpret_cast<const uint8_t *>(frame.data()), frame.size()).c_str());

  if (this->is_session_iv_request_(frame)) {
    // The IV request advertises which key_id the keypad will use for the
    // rest of the session (`57 00 00 00 0F 21 03 <key_id>`). Adapt to it —
    // Original/Touch uses 0x88, Vision/Vision Pro uses 0xC6.
    const uint8_t requested_slot = static_cast<uint8_t>(frame[7]);
    if (requested_slot != this->shared_slot_id_) {
      ESP_LOGI(TAG, "Token slot: 0x%02X", requested_slot);
      this->shared_slot_id_ = requested_slot;
    }
    ESP_LOGD(TAG, "IV request");
    this->send_session_iv_();
    return;
  }

  if (frame.size() <= ENCRYPTED_HEADER ||
      static_cast<uint8_t>(frame[0]) != PROTOCOL_MAGIC) {
    ESP_LOGD(TAG, "Ignoring non-protocol frame (size=%zu)", frame.size());
    return;
  }

  const FrameHeader header{static_cast<uint8_t>(frame[1]), static_cast<uint8_t>(frame[2]),
                           static_cast<uint8_t>(frame[3])};

  if (header.key_id != this->shared_slot_id_) {
    ESP_LOGD(TAG, "Ignoring frame with unexpected key_id=0x%02X", header.key_id);
    return;
  }

  // Refuse encrypted frames before the IV handshake completed in this session.
  // A captured ciphertext from a previous connection would otherwise decrypt
  // against the wrong (or stale) IV and ride on whatever lock_state_ is set.
  if (!this->iv_established_) {
    ESP_LOGW(TAG, "Dropping encrypted frame: no IV negotiated in this session");
    return;
  }

  // The protocol echoes IV[0..1] back as the seq_a/seq_b header bytes.
  // Reject anything that does not match the IV we just issued — this blocks
  // cross-session replay of captured ciphertexts.
  if (header.seq_a != this->session_iv_response_[IV_RESPONSE_HEADER] ||
      header.seq_b != this->session_iv_response_[IV_RESPONSE_HEADER + 1]) {
    ESP_LOGW(TAG, "Dropping frame: seq_a/seq_b mismatch (cross-session replay?)");
    return;
  }

  const size_t ct_len = frame.size() - ENCRYPTED_HEADER;
  if (ct_len > MAX_PAYLOAD_LEN) {
    ESP_LOGW(TAG, "Dropping frame with invalid payload length: %zu", ct_len);
    return;
  }

  const uint8_t *ciphertext = reinterpret_cast<const uint8_t *>(frame.data() + ENCRYPTED_HEADER);

  // Intra-session replay protection for state-changing actions: under a
  // fixed session IV, identical plaintexts produce identical ciphertexts.
  // We only flag duplicates that decode to a side-effecting command — state
  // polls are idempotent and a legitimate keypad emits them repeatedly.
  const bool ciphertext_seen = this->is_replayed_ciphertext_(ciphertext, ct_len);

  uint8_t plaintext[MAX_PAYLOAD_LEN];
  if (!this->aes_ctr_xcrypt_(ciphertext, ct_len, plaintext)) {
    return;  // error already logged
  }

  ESP_LOGD(TAG, "RX %s", format_hex_pretty(plaintext, ct_len).c_str());

  DecodedCommand command;
  if (!this->decode_command_(plaintext, ct_len, command)) {
    ESP_LOGI(TAG, "Unhandled command: %s", format_hex_pretty(plaintext, ct_len).c_str());
    this->send_ack_(header);
    return;
  }

  if (command.type == CommandType::LOCK || command.type == CommandType::UNLOCK) {
    if (ciphertext_seen) {
      ESP_LOGW(TAG, "Dropping action: ciphertext replay within session");
      return;
    }
    this->record_ciphertext_(ciphertext, ct_len);
  }

  this->handle_command_(header, command);
}

bool SwitchbotKeypadBridge::is_session_iv_request_(const std::string &frame) const {
  return frame.size() >= SESSION_IV_REQ_MIN &&
         static_cast<uint8_t>(frame[0]) == PROTOCOL_MAGIC &&
         static_cast<uint8_t>(frame[1]) == 0x00 &&
         static_cast<uint8_t>(frame[5]) == 0x21 &&
         static_cast<uint8_t>(frame[6]) == 0x03;
}

void SwitchbotKeypadBridge::send_session_iv_() {
  this->rotate_session_iv_();
  // A new IV invalidates any ciphertext sniffed under the previous one.
  this->clear_replay_history_();
  this->iv_established_ = true;
  this->notify_(this->session_iv_response_.data(), this->session_iv_response_.size());
}

bool SwitchbotKeypadBridge::decode_command_(const uint8_t *plaintext, size_t length,
                                            DecodedCommand &out) const {
  if (length == sizeof(FRAME_LOCK) && std::memcmp(plaintext, FRAME_LOCK, sizeof(FRAME_LOCK)) == 0) {
    out.type = CommandType::LOCK;
    return true;
  }
  if (length == 4 &&
      std::memcmp(plaintext, FRAME_STATE_POLL_PREFIX, sizeof(FRAME_STATE_POLL_PREFIX)) == 0) {
    out.type = CommandType::STATE_POLL;
    return true;
  }
  if (length == sizeof(FRAME_DOORBELL) &&
      std::memcmp(plaintext, FRAME_DOORBELL, sizeof(FRAME_DOORBELL)) == 0) {
    out.type = CommandType::DOORBELL;
    return true;
  }
  if (length >= 8 && std::memcmp(plaintext, FRAME_ACTION, sizeof(FRAME_ACTION)) == 0 &&
      plaintext[UNLOCK_MARKER_OFFSET] == UNLOCK_MARKER) {
    out.type = CommandType::UNLOCK;
    const uint8_t method_byte = plaintext[UNLOCK_METHOD_OFFSET];
    out.method = static_cast<UnlockMethod>(method_byte);
    const uint8_t idx_byte = plaintext[UNLOCK_INDEX_OFFSET];
    // Original keypad: index encoded as 0x0A + zero-based slot. Vision: raw
    // zero-based byte (we only have a single capture with 0x00, so this is
    // a best-effort decode). Heuristic: if the byte ≥ 0x0A, treat as the
    // original biased encoding; otherwise pass it through as the raw index.
    out.credential_index = (idx_byte >= UNLOCK_INDEX_BASE)
                               ? static_cast<int16_t>(idx_byte - UNLOCK_INDEX_BASE)
                               : static_cast<int16_t>(idx_byte);
    return true;
  }
  return false;
}

void SwitchbotKeypadBridge::handle_command_(const FrameHeader &header, const DecodedCommand &command) {
  switch (command.type) {
    case CommandType::LOCK:
      ESP_LOGI(TAG, "Lock");
      this->lock_state_ = LockState::LOCKED;
      this->publish_lock_();
      this->send_encrypted_response_(header, RESPONSE_LOCK, sizeof(RESPONSE_LOCK));
      return;

    case CommandType::UNLOCK:
      ESP_LOGI(TAG, "Unlock: method=%s (0x%02X) index=%d",
               unlock_method_name(command.method),
               static_cast<uint8_t>(command.method), command.credential_index);
      this->lock_state_ = LockState::UNLOCKED;
      this->publish_unlock_(command.method, command.credential_index);
      this->send_encrypted_response_(header, RESPONSE_UNLOCK, sizeof(RESPONSE_UNLOCK));
      return;

    case CommandType::STATE_POLL:
      ESP_LOGV(TAG, "State poll");
      this->handle_state_poll_(header);
      return;

    case CommandType::DOORBELL:
      ESP_LOGI(TAG, "Doorbell");
      this->publish_doorbell_();
      // No lock-state change; the keypad only needs the transport ACK.
      this->send_ack_(header);
      return;

    case CommandType::UNKNOWN:
    default:
      this->send_ack_(header);
      return;
  }
}

void SwitchbotKeypadBridge::handle_state_poll_(const FrameHeader &header) {
  uint8_t state_payload[1 + sizeof(STATE_PAYLOAD_TAIL)];
  state_payload[0] = static_cast<uint8_t>(this->lock_state_);
  std::memcpy(state_payload + 1, STATE_PAYLOAD_TAIL, sizeof(STATE_PAYLOAD_TAIL));
  this->send_encrypted_response_(header, state_payload, sizeof(state_payload));
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::send_ack_(const FrameHeader &header) {
  const uint8_t ack[ENCRYPTED_HEADER] = {0x01, header.key_id, header.seq_a, header.seq_b};
  this->notify_(ack, sizeof(ack));
}

void SwitchbotKeypadBridge::send_encrypted_response_(const FrameHeader &header,
                                                    const uint8_t *plaintext, size_t length) {
  if (length > MAX_PAYLOAD_LEN) {
    ESP_LOGE(TAG, "Response payload too large (%zu > %zu)", length, MAX_PAYLOAD_LEN);
    return;
  }
  uint8_t packet[ENCRYPTED_HEADER + MAX_PAYLOAD_LEN];
  packet[0] = 0x01;
  packet[1] = header.key_id;
  packet[2] = header.seq_a;
  packet[3] = header.seq_b;
  if (!this->aes_ctr_xcrypt_(plaintext, length, packet + ENCRYPTED_HEADER)) {
    return;
  }
  this->notify_(packet, ENCRYPTED_HEADER + length);
}

void SwitchbotKeypadBridge::notify_(const uint8_t *data, size_t length) {
  this->tx_characteristic_->setValue(data, length);
  this->tx_characteristic_->notify();
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

bool SwitchbotKeypadBridge::aes_ctr_xcrypt_(const uint8_t *input, size_t length, uint8_t *output) {
  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  size_t out_len = 0;
  size_t finish_len = 0;

  psa_status_t status = psa_cipher_encrypt_setup(&op, this->aes_key_handle_, PSA_ALG_CTR);
  if (status == PSA_SUCCESS) {
    status = psa_cipher_set_iv(&op, this->session_iv_response_.data() + IV_RESPONSE_HEADER, AES_IV_SIZE);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_update(&op, input, length, output, length, &out_len);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_finish(&op, output + out_len, length - out_len, &finish_len);
  }

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES-CTR operation failed (%d)", static_cast<int>(status));
    psa_cipher_abort(&op);
    return false;
  }
  return true;
}

void SwitchbotKeypadBridge::rotate_session_iv_() {
  for (size_t i = 0; i < AES_IV_SIZE; i += 4) {
    const uint32_t value = esp_random();
    std::memcpy(this->session_iv_response_.data() + IV_RESPONSE_HEADER + i, &value, 4);
  }
  ESP_LOGV(TAG, "IV rotated: %s",
           format_hex_pretty(this->session_iv_response_.data() + IV_RESPONSE_HEADER, AES_IV_SIZE).c_str());
}

// ---------------------------------------------------------------------------
// Anti-replay
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::reset_session_state_() {
  this->iv_established_ = false;
  this->clear_replay_history_();
}

void SwitchbotKeypadBridge::clear_replay_history_() {
  this->replay_head_ = 0;
  for (auto &entry : this->replay_history_) {
    entry.length = 0;
  }
}

bool SwitchbotKeypadBridge::is_replayed_ciphertext_(const uint8_t *ciphertext, size_t length) const {
  if (length == 0 || length > MAX_REPLAY_PAYLOAD) {
    return false;
  }
  for (const auto &entry : this->replay_history_) {
    if (entry.length == length && std::memcmp(entry.data.data(), ciphertext, length) == 0) {
      return true;
    }
  }
  return false;
}

void SwitchbotKeypadBridge::record_ciphertext_(const uint8_t *ciphertext, size_t length) {
  if (length == 0 || length > MAX_REPLAY_PAYLOAD) {
    return;
  }
  ReplayEntry &slot = this->replay_history_[this->replay_head_];
  std::memcpy(slot.data.data(), ciphertext, length);
  slot.length = length;
  this->replay_head_ = (this->replay_head_ + 1) % REPLAY_HISTORY_SIZE;
}

// ---------------------------------------------------------------------------
// Eventing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::publish_lock_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Lock");
  }
  this->on_lock_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_unlock_(UnlockMethod method, int index) {
  const char *method_str = unlock_method_name(method);
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Unlock");
  }
  this->on_unlock_callbacks_.call(std::string(method_str), index);
}

void SwitchbotKeypadBridge::publish_doorbell_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Doorbell");
  }
  this->on_doorbell_callbacks_.call();
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
