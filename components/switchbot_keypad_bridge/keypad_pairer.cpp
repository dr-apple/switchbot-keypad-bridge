#include "keypad_pairer.h"

#include <host/ble_gap.h>
#include <psa/crypto.h>

#include <cstdio>
#include <cstring>

#include "esphome/core/log.h"
#include "keypad_advert.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.pairer";

// GATT UUIDs published by every SwitchBot lock / keypad.
constexpr const char *SERVICE_UUID = "cba20d00-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *RX_CHAR_UUID = "cba20002-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *TX_CHAR_UUID = "cba20003-224d-11e6-9fb8-0002a5d5c51b";

// Per-family pairing dialect: the BLE handshake constants that differ
// between the Original and Vision keypad families.
struct FamilyPreset {
  uint8_t shared_slot;
  uint8_t slot_init_nonce;
  const uint8_t *enter_pairing;
  size_t enter_pairing_len;
  const uint8_t *capabilities_probe;  // may be nullptr
  size_t capabilities_probe_len;
  const uint8_t *finalize_tail;
  size_t finalize_tail_len;
};

constexpr uint8_t ORIGINAL_ENTER_PAIRING[]   = {0x0f, 0x52, 0x01, 0x07, 0x00};
constexpr uint8_t ORIGINAL_FINALIZE_TAIL[]   = {0x00, 0x08, 0x09, 0x04, 0x05, 0x07};

constexpr uint8_t VISION_ENTER_PAIRING[]     = {0x0f, 0x53, 0x01, 0x07};
constexpr uint8_t VISION_CAPABILITIES_PROBE[]= {0x0f, 0x53, 0x07, 0x03};
constexpr uint8_t VISION_FINALIZE_TAIL[]     = {0x04, 0x04, 0x01, 0x05, 0x08, 0x09};

constexpr FamilyPreset ORIGINAL_PRESET = {
    0x88, 0x69,
    ORIGINAL_ENTER_PAIRING,    sizeof(ORIGINAL_ENTER_PAIRING),
    nullptr,                   0,
    ORIGINAL_FINALIZE_TAIL,    sizeof(ORIGINAL_FINALIZE_TAIL),
};
constexpr FamilyPreset VISION_PRESET = {
    0xC6, 0x80,
    VISION_ENTER_PAIRING,      sizeof(VISION_ENTER_PAIRING),
    VISION_CAPABILITIES_PROBE, sizeof(VISION_CAPABILITIES_PROBE),
    VISION_FINALIZE_TAIL,      sizeof(VISION_FINALIZE_TAIL),
};

const FamilyPreset &preset_for(CloudClient::KeypadFamily f) {
  return f == CloudClient::KeypadFamily::VISION ? VISION_PRESET : ORIGINAL_PRESET;
}

// Friendly step labels — kept short so the UI's progress card stays tidy.
// Keep these in lock-step with the <ul class="stepper"> list in
// pairing_ui.html: same count, same order, same wording.
constexpr const char *STEP_LABELS[] = {
    "Connecting to keypad",
    "Discovering services",
    "Negotiating session key",
    "Opening lock slot",
    "Writing shared key (1/2)",
    "Writing shared key (2/2)",
    "Updating lock target",
    "Finalising",
};
constexpr uint8_t TOTAL_STEPS = sizeof(STEP_LABELS) / sizeof(STEP_LABELS[0]);

// AES-128-CTR via PSA Crypto. The keypad K14 only lives for the
// duration of one pairing run, so we import the key fresh each time
// and destroy it at the end of the call.  Same primitive the runtime
// decrypt path uses — no extra IDF component dependency.
bool aes_ctr_xcrypt(const uint8_t *key, const uint8_t iv[16],
                    const uint8_t *in, uint8_t *out, size_t length) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t s = psa_import_key(&attrs, key, 16, &key_id);
  psa_reset_key_attributes(&attrs);
  if (s != PSA_SUCCESS) return false;

  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  size_t out_len = 0, finish_len = 0;
  s = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
  if (s == PSA_SUCCESS) s = psa_cipher_set_iv(&op, iv, 16);
  if (s == PSA_SUCCESS) s = psa_cipher_update(&op, in, length, out, length, &out_len);
  if (s == PSA_SUCCESS) s = psa_cipher_finish(&op, out + out_len, length - out_len, &finish_len);
  if (s != PSA_SUCCESS) psa_cipher_abort(&op);

  psa_destroy_key(key_id);
  return s == PSA_SUCCESS;
}

// Read the SwitchBot service-data blob from an advertisement (UUID 0xFD3D,
// with the legacy 0x0D00 as a fallback). Empty when the device isn't
// advertising SwitchBot service data.
std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv) {
  static const NimBLEUUID U_FD3D(static_cast<uint16_t>(0xFD3D));
  static const NimBLEUUID U_0D00(static_cast<uint16_t>(0x0D00));
  std::string sd = adv->getServiceData(U_FD3D);
  if (sd.empty()) sd = adv->getServiceData(U_0D00);
  return std::vector<uint8_t>(sd.begin(), sd.end());
}

// Briefly scan and look up the advertising packet of the target MAC so
// we can connect with the right address type. The keypad's first byte
// (top 2 bits = 11) makes it a BLE "random static" address; without a
// scan we'd have to guess between PUBLIC and RANDOM. Returns the
// address with the discovered type on success, an empty address on
// timeout. On success, `ident_out` carries the keypad model/family read
// from the advertisement (pySwitchbot-style); `ident_out.is_keypad` is
// false when the advert didn't match a known signature.
NimBLEAddress discover_target(const std::string &mac_pretty, uint32_t timeout_ms,
                             KeypadIdent &ident_out) {
  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(30);

  std::string target = mac_pretty;
  for (auto &c : target) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }

  NimBLEScanResults results = scan->getResults(timeout_ms, false);
  for (int i = 0; i < results.getCount(); ++i) {
    const NimBLEAdvertisedDevice *adv = results.getDevice(i);
    std::string found = adv->getAddress().toString();
    for (auto &c : found) {
      if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    if (found == target) {
      const std::vector<uint8_t> sd = switchbot_service_data(adv);
      ident_out = identify_keypad(sd.data(), sd.size());
      ESP_LOGI(TAG, "Found keypad %s (addr_type=%d, advert=%s)",
               mac_pretty.c_str(), adv->getAddressType(),
               ident_out.is_keypad ? ident_out.display_name : "unrecognised");
      return adv->getAddress();
    }
  }
  return NimBLEAddress{};
}

}  // namespace

// ── Lifecycle ─────────────────────────────────────────────────────────────

std::string KeypadPairer::start(Request req) {
  {
    std::lock_guard<std::mutex> lk(this->mu_);
    if (this->status_.state == State::RUNNING) {
      return "";  // refuse concurrent jobs
    }
  }

  // Generate a job id — millis() is fine, monotonic enough for polling.
  char job_buf[16];
  std::snprintf(job_buf, sizeof(job_buf), "p-%lu",
                static_cast<unsigned long>(esp_timer_get_time() / 1000));
  std::string job_id = job_buf;

  // Move the request into a heap-allocated copy that the task takes
  // ownership of.
  auto *req_heap = new Request(std::move(req));

  // Stash the things the notification callback needs right now —
  // the request goes to the task that frees it.
  this->key_      = req_heap->key;
  this->key_id_   = static_cast<uint8_t>(req_heap->key_id);
  this->iv_received_ = false;

  // One-slot ACK semaphore (counting=1 with initial value 0).
  if (this->ack_sem_ == nullptr) {
    this->ack_sem_ = xSemaphoreCreateBinary();
  }
  while (xSemaphoreTake(this->ack_sem_, 0) == pdTRUE) { /* drain */ }

  this->set_running_(TOTAL_STEPS, job_id);

  // Spawn the task. The trampoline forwards to execute_() and frees the
  // request when done.
  struct TaskCtx {
    KeypadPairer *self;
    Request      *req;
  };
  auto *ctx = new TaskCtx{this, req_heap};

  BaseType_t rc = xTaskCreatePinnedToCore(
      [](void *raw) {
        auto *c = static_cast<TaskCtx *>(raw);
        c->self->execute_(*c->req);
        delete c->req;
        c->self->task_handle_ = nullptr;
        delete c;
        vTaskDelete(nullptr);
      },
      "kp-pair", 8192, ctx,
      tskIDLE_PRIORITY + 2, &this->task_handle_,
      // Pin to the BT task's core (typically 0) so the NimBLE callbacks
      // and our central operations don't bounce across cores.
      0);

  if (rc != pdPASS) {
    delete ctx;
    delete req_heap;
    this->set_failed_("Could not start pairing task");
    return "";
  }
  return job_id;
}

KeypadPairer::Status KeypadPairer::status() const {
  std::lock_guard<std::mutex> lk(this->mu_);
  return this->status_;
}

// ── Status helpers ────────────────────────────────────────────────────────

void KeypadPairer::set_running_(uint8_t total, const std::string &job_id) {
  std::lock_guard<std::mutex> lk(this->mu_);
  this->status_.state   = State::RUNNING;
  this->status_.step    = 0;
  this->status_.total   = total;
  this->status_.message = STEP_LABELS[0];
  this->status_.error.clear();
  this->status_.job_id  = job_id;
}

void KeypadPairer::set_step_(uint8_t step, const char *msg) {
  ESP_LOGI(TAG, "step %u/%u: %s", static_cast<unsigned>(step + 1),
           static_cast<unsigned>(TOTAL_STEPS), msg);
  std::lock_guard<std::mutex> lk(this->mu_);
  this->status_.step    = step;
  this->status_.message = msg;
}

void KeypadPairer::set_success_() {
  ESP_LOGI(TAG, "pairing successful");
  std::lock_guard<std::mutex> lk(this->mu_);
  this->status_.state   = State::SUCCESS;
  this->status_.step    = this->status_.total;
  this->status_.message = "Pairing complete";
  this->status_.error.clear();
}

void KeypadPairer::set_failed_(const std::string &err) {
  ESP_LOGW(TAG, "pairing failed: %s", err.c_str());
  std::lock_guard<std::mutex> lk(this->mu_);
  this->status_.state   = State::FAILED;
  this->status_.error   = err;
  this->status_.message = err;
}

// ── BLE notification sink ─────────────────────────────────────────────────

void KeypadPairer::on_notify_(const uint8_t *data, size_t length) {
  // This runs on the NimBLE host task — a task context, not an ISR — so
  // the plain xSemaphoreGive() is the correct primitive here.
  //
  // The session-IV reply is the only notification with a payload we
  // actually need to inspect. Everything else just bumps the ACK
  // semaphore so send_command_() can move on.
  if (length == 20 && data[0] == 0x01 && data[1] == 0x00) {
    std::memcpy(this->iv_.data(), data + 4, 16);
    this->iv_received_.store(true);
  }
  if (this->ack_sem_ != nullptr) {
    xSemaphoreGive(this->ack_sem_);
  }
}

// ── Encrypted send ────────────────────────────────────────────────────────

bool KeypadPairer::send_command_(NimBLERemoteCharacteristic *rx,
                                 const uint8_t *plaintext, size_t plaintext_len) {
  // Encrypted frame layout (same as the existing keypad command path):
  //   [0x57][key_id][IV[0]][IV[1]][AES-CTR(K14, IV, plaintext)]
  std::vector<uint8_t> frame(4 + plaintext_len);
  frame[0] = 0x57;
  frame[1] = this->key_id_;
  frame[2] = this->iv_[0];
  frame[3] = this->iv_[1];
  if (!aes_ctr_xcrypt(this->key_.data(), this->iv_.data(),
                      plaintext, frame.data() + 4, plaintext_len)) {
    return false;
  }

  // Drain any stale ACK before issuing the write.
  while (xSemaphoreTake(this->ack_sem_, 0) == pdTRUE) { /* drain */ }
  if (!rx->writeValue(frame.data(), frame.size(), /*response=*/true)) {
    return false;
  }
  // Wait briefly for the ACK notification. We tolerate a missing ACK on most
  // steps — the keypad doesn't always respond to the cosmetic commands.
  xSemaphoreTake(this->ack_sem_, pdMS_TO_TICKS(800));
  return true;
}

// ── Task body ─────────────────────────────────────────────────────────────

void KeypadPairer::execute_(Request &req) {
  // Step 0: discover the target via an active scan, then connect with
  // the correct address type. Without the scan we'd have to guess
  // between PUBLIC and RANDOM, and the BLE spec uses the top bits of
  // the MAC to encode the type — but the cloud only gives us the bare
  // bytes, not the type. Scanning is also the natural check that the
  // keypad is in range right now.
  this->set_step_(0, STEP_LABELS[0]);
  KeypadIdent ident;
  NimBLEAddress target = discover_target(req.keypad_mac, 6000, ident);
  if (target.isNull()) {
    this->set_failed_("Could not see the keypad over BLE. Keep it within 2 m and retry.");
    return;
  }

  // The keypad model — and therefore the pairing dialect — comes solely from
  // the live advertisement. If we can't identify it, we don't guess.
  if (!ident.is_keypad) {
    this->set_failed_("Could not identify the keypad from its advertisement. "
                      "Reset it into pairing mode, keep it within 2 m and retry.");
    return;
  }
  ESP_LOGI(TAG, "Pairing %s as %s family", ident.display_name,
           ident.family == CloudClient::KeypadFamily::VISION ? "VISION" : "ORIGINAL");
  const FamilyPreset &preset = preset_for(ident.family);

  // The keypad might currently be connected to our peripheral (server) role —
  // it sends IV requests to us as a SwitchBot Lock emulation. The BLE spec
  // allows only one ACL link between two peers, so we must terminate that
  // link before the central connect, otherwise connect() will always fail.
  {
    struct ble_gap_conn_desc desc{};
    if (ble_gap_conn_find_by_addr(target.getBase(), &desc) == 0) {
      ESP_LOGI(TAG, "Keypad still connected as peripheral (h=%u) — terminating before pair",
               desc.conn_handle);
      ble_gap_terminate(desc.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
      vTaskDelay(pdMS_TO_TICKS(600));
    }
  }

  NimBLEClient *client = NimBLEDevice::createClient();
  client->setConnectTimeout(10000);  // ms (NimBLE-cpp 2.x uses ms, not seconds)
  if (!client->connect(target)) {
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Could not connect to the keypad. Keep it within 2 m and retry.");
    return;
  }

  // Step 1: discover service + characteristics.
  this->set_step_(1, STEP_LABELS[1]);
  NimBLERemoteService *svc = client->getService(NimBLEUUID(SERVICE_UUID));
  NimBLERemoteCharacteristic *rx = nullptr;
  NimBLERemoteCharacteristic *tx = nullptr;
  if (svc != nullptr) {
    rx = svc->getCharacteristic(NimBLEUUID(RX_CHAR_UUID));
    tx = svc->getCharacteristic(NimBLEUUID(TX_CHAR_UUID));
  }
  if (rx == nullptr || tx == nullptr) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Keypad does not expose the SwitchBot GATT service.");
    return;
  }

  // Subscribe to TX notifications.
  tx->subscribe(true,
                [this](NimBLERemoteCharacteristic *, uint8_t *data,
                       size_t length, bool /*is_notify*/) {
                  this->on_notify_(data, length);
                });

  // Step 2: IV request.
  this->set_step_(2, STEP_LABELS[2]);
  while (xSemaphoreTake(this->ack_sem_, 0) == pdTRUE) { /* drain */ }
  uint8_t iv_req[8] = {0x57, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03,
                       this->key_id_};
  if (!rx->writeValue(iv_req, sizeof(iv_req), /*response=*/true)) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Could not request session IV from keypad.");
    return;
  }
  // Give the keypad up to 3 s to reply with the 20-byte IV frame.
  for (int i = 0; i < 6 && !this->iv_received_.load(); ++i) {
    xSemaphoreTake(this->ack_sem_, pdMS_TO_TICKS(500));
  }
  if (!this->iv_received_.load()) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Keypad did not open a session. Reset it into pairing mode and retry.");
    return;
  }

  // Steps 3..7: the pairing commands proper. Helper that reports a step,
  // sends a plaintext command, and surfaces a friendly error on failure.
  auto run_step = [&](uint8_t step, const uint8_t *pt, size_t pt_len,
                      const char *err_msg) -> bool {
    this->set_step_(step, STEP_LABELS[step]);
    if (!this->send_command_(rx, pt, pt_len)) {
      client->disconnect();
      NimBLEDevice::deleteClient(client);
      this->set_failed_(err_msg);
      return false;
    }
    return true;
  };

  // Step 3: open lock slot. Original keypads send the enter_pairing
  // command directly; Vision keypads additionally precede it with a
  // capabilities probe.
  this->set_step_(3, STEP_LABELS[3]);
  if (!this->send_command_(rx, preset.enter_pairing, preset.enter_pairing_len)) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("enter_pairing rejected.");
    return;
  }
  if (preset.capabilities_probe != nullptr) {
    this->send_command_(rx, preset.capabilities_probe, preset.capabilities_probe_len);
  }
  uint8_t prep[] = {0x06, 0x03};
  this->send_command_(rx, prep, sizeof(prep));
  uint8_t slot_init[] = {0x0F, 0x20, 0x03, preset.shared_slot, preset.slot_init_nonce};
  this->send_command_(rx, slot_init, sizeof(slot_init));

  // Step 4: shared_key chunk 1.
  uint8_t tok1[5 + 8];
  tok1[0] = 0x0F; tok1[1] = 0x20; tok1[2] = 0x04;
  tok1[3] = preset.shared_slot; tok1[4] = 0x00;
  std::memcpy(tok1 + 5, req.shared_token.data(), 8);
  if (!run_step(4, tok1, sizeof(tok1), "Could not write shared_key (1/2).")) return;

  // Step 5: shared_key chunk 2.
  uint8_t tok2[5 + 8];
  tok2[0] = 0x0F; tok2[1] = 0x20; tok2[2] = 0x04;
  tok2[3] = preset.shared_slot; tok2[4] = 0x01;
  std::memcpy(tok2 + 5, req.shared_token.data() + 8, 8);
  if (!run_step(5, tok2, sizeof(tok2), "Could not write shared_key (2/2).")) return;

  // Step 6: change keypad's lock target to our ESP MAC.
  uint8_t mac_payload[3 + 6];
  mac_payload[0] = 0x06; mac_payload[1] = 0x01; mac_payload[2] = preset.shared_slot;
  std::memcpy(mac_payload + 3, req.esp_mac.data(), 6);
  if (!run_step(6, mac_payload, sizeof(mac_payload), "Could not update target lock MAC.")) return;

  // Step 7: finalize.
  this->set_step_(7, STEP_LABELS[7]);
  {
    std::vector<uint8_t> fin = {0x0f, 0x52, 0x02, 0x02, 0x10, 0xFF, 0x05, 0x06};
    fin.insert(fin.end(), preset.finalize_tail,
               preset.finalize_tail + preset.finalize_tail_len);
    this->send_command_(rx, fin.data(), fin.size());
  }
  uint8_t finalize2[] = {0x0f, 0x53, 0x01, 0x06};
  this->send_command_(rx, finalize2, sizeof(finalize2));

  // Cleanup.
  client->disconnect();
  NimBLEDevice::deleteClient(client);

  this->set_success_();
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
