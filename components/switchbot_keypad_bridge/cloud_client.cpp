#include "cloud_client.h"

#include <cctype>
#include <cstring>
#include <ctime>

#include <cJSON.h>
#include <esp_crt_bundle.h>
#include <esp_http_client.h>
#include <esp_tls.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.cloud";

// The OAuth-style clientId the official SwitchBot app uses.
constexpr const char *CLIENT_ID = "5nnwmhmsa9xxskm14hd85lm9bm";

constexpr const char *ACCOUNT_BASE = "https://account.api.switchbot.net";

// NOTE: keypads are no longer identified by their cloud SKU. The cloud is used
// only to enumerate the account's devices (MAC + name) and to fetch each
// keypad's communication key. Whether a device *is* a keypad — and which
// protocol family it speaks — is decided solely from its BLE advertisement, the
// way the official pySwitchbot library does it (see keypad_advert.h). This keeps
// us from chasing SwitchBot's ever-growing list of device_type codes.

// Convert "B0E9FE612E75" → "B0:E9:FE:61:2E:75". Idempotent on already-
// pretty input. Defensive on odd-length strings (returns input as-is).
std::string pretty_mac(const std::string &raw) {
  std::string compact;
  compact.reserve(12);
  for (char c : raw) {
    if (c == ':' || c == '-')
      continue;
    compact.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  if (compact.size() != 12) return raw;
  std::string out;
  out.reserve(17);
  for (size_t i = 0; i < 12; i += 2) {
    if (!out.empty()) out.push_back(':');
    out.push_back(compact[i]);
    out.push_back(compact[i + 1]);
  }
  return out;
}

std::string compact_mac(const std::string &any) {
  std::string out;
  out.reserve(12);
  for (char c : any) {
    if (c == ':' || c == '-')
      continue;
    out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  return out;
}

// Build a JSON object string for the simple `{"k": "v", ...}` requests
// we need.  Just enough to avoid pulling in a full JSON library on the
// write side — we already use cJSON to read.
std::string build_login_body(const std::string &email,
                             const std::string &password) {
  // No JSON escaping for email/password — SwitchBot account emails and
  // passwords realistically never contain `"` or `\`. If they do, login
  // fails cleanly with an API error.
  std::string body;
  body.reserve(160 + email.size() + password.size());
  body += R"json({"clientId":")json";
  body += CLIENT_ID;
  body += R"json(","username":")json";
  body += email;
  body += R"json(","password":")json";
  body += password;
  body += R"json(","grantType":"password","verifyCode":""})json";
  return body;
}

// Body recipient for esp_http_client. We accumulate into a std::string
// owned by user_data, growing as data comes in.
esp_err_t http_event_handler(esp_http_client_event_t *evt) {
  if (evt->event_id == HTTP_EVENT_ON_DATA && evt->user_data != nullptr) {
    auto *buf = static_cast<std::string *>(evt->user_data);
    buf->append(static_cast<const char *>(evt->data),
                static_cast<size_t>(evt->data_len));
  }
  return ESP_OK;
}

// cJSON convenience: parse and extract the body's `statusCode` (which
// SwitchBot APIs always set to 100 on success). Returns the parsed
// cJSON root on success; the caller must `cJSON_Delete` it.
cJSON *parse_envelope(const std::string &body, int &status_code,
                      std::string &message) {
  cJSON *root = cJSON_ParseWithLength(body.data(), body.size());
  if (root == nullptr) {
    return nullptr;
  }
  cJSON *sc = cJSON_GetObjectItemCaseSensitive(root, "statusCode");
  status_code = cJSON_IsNumber(sc) ? sc->valueint : -1;
  cJSON *msg = cJSON_GetObjectItemCaseSensitive(root, "message");
  message = (cJSON_IsString(msg) && msg->valuestring) ? msg->valuestring : "";
  return root;
}

bool parse_hex_byte(const char *s, uint8_t &out) {
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  int hi = digit(s[0]);
  int lo = digit(s[1]);
  if (hi < 0 || lo < 0) return false;
  out = static_cast<uint8_t>((hi << 4) | lo);
  return true;
}

bool parse_hex_string(const std::string &hex, std::vector<uint8_t> &out) {
  if (hex.size() % 2 != 0) return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t b;
    if (!parse_hex_byte(hex.c_str() + i, b)) return false;
    out.push_back(b);
  }
  return true;
}

}  // namespace

// ── HTTPS plumbing ────────────────────────────────────────────────────────

bool CloudClient::post_json_(const std::string &url, const std::string &body,
                             const std::string &bearer, std::string &out,
                             std::string &error_out) {
  out.clear();

  // TLS cert validation needs a valid system clock — at first boot the ESP32
  // wakes up at the epoch, so cert.notBefore checks fail and the handshake
  // errors out as ESP_ERR_HTTP_CONNECT. Wait briefly for SNTP (or HA-API
  // sync) to set the clock before issuing the request.
  constexpr time_t MIN_VALID_TIME = 1700000000;  // 2023-11-14
  const TickType_t start = xTaskGetTickCount();
  while (time(nullptr) < MIN_VALID_TIME) {
    if ((xTaskGetTickCount() - start) > pdMS_TO_TICKS(10000)) {
      error_out = "Device clock not set — TLS needs a valid system time. Add "
                  "`time: - platform: sntp` to the YAML, or wait until Home "
                  "Assistant connects (its API component syncs the clock).";
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(200));
  }

  esp_http_client_config_t cfg = {};
  cfg.url = url.c_str();
  cfg.method = HTTP_METHOD_POST;
  cfg.event_handler = http_event_handler;
  cfg.user_data = &out;
  cfg.transport_type = HTTP_TRANSPORT_OVER_SSL;
  cfg.crt_bundle_attach = esp_crt_bundle_attach;
  cfg.timeout_ms = 8000;
  cfg.buffer_size = 1024;
  cfg.buffer_size_tx = 1024;

  esp_http_client_handle_t client = esp_http_client_init(&cfg);
  if (client == nullptr) {
    error_out = "esp_http_client_init failed";
    return false;
  }

  esp_http_client_set_header(client, "Content-Type", "application/json");
  esp_http_client_set_header(client, "Accept", "application/json");
  if (!bearer.empty()) {
    esp_http_client_set_header(client, "authorization", bearer.c_str());
  }
  esp_http_client_set_post_field(client, body.c_str(),
                                 static_cast<int>(body.size()));

  esp_err_t err = esp_http_client_perform(client);
  bool ok = false;
  if (err != ESP_OK) {
    error_out = "HTTPS request failed: ";
    error_out += esp_err_to_name(err);
  } else {
    int status = esp_http_client_get_status_code(client);
    if (status / 100 != 2) {
      error_out = "HTTP ";
      error_out += std::to_string(status);
      // Body may still be useful for diagnostics.
      ESP_LOGW(TAG, "%s -> %d, body: %s", url.c_str(), status, out.c_str());
    } else {
      ok = true;
    }
  }
  esp_http_client_cleanup(client);
  return ok;
}

std::string CloudClient::wonderlabs_base_() const {
  std::string url = "https://wonderlabs.";
  url += this->region_.empty() ? "us" : this->region_;
  url += ".api.switchbot.net";
  return url;
}

// ── Public API ────────────────────────────────────────────────────────────

bool CloudClient::login(const std::string &email, const std::string &password,
                        std::string &error_out) {
  this->clear();

  // Step 1: account login -> bearer token.
  {
    std::string url = std::string(ACCOUNT_BASE) + "/account/api/v1/user/login";
    std::string body = build_login_body(email, password);
    std::string response;
    if (!this->post_json_(url, body, "", response, error_out)) {
      return false;
    }

    int sc = -1;
    std::string msg;
    cJSON *root = parse_envelope(response, sc, msg);
    if (root == nullptr) {
      error_out = "Login response was not valid JSON";
      return false;
    }
    if (sc != 100) {
      error_out = msg.empty() ? "Login rejected" : msg;
      cJSON_Delete(root);
      return false;
    }
    cJSON *body_obj = cJSON_GetObjectItemCaseSensitive(root, "body");
    cJSON *tok = body_obj ? cJSON_GetObjectItemCaseSensitive(body_obj, "access_token") : nullptr;
    if (!cJSON_IsString(tok) || tok->valuestring == nullptr) {
      error_out = "Login succeeded but no access_token returned";
      cJSON_Delete(root);
      return false;
    }
    this->auth_token_ = tok->valuestring;
    cJSON_Delete(root);
  }

  // Step 2: userinfo -> region. Failure here is non-fatal: we default
  // to "us" and continue.
  this->region_ = "us";
  {
    std::string url = std::string(ACCOUNT_BASE) + "/account/api/v1/user/userinfo";
    std::string response;
    std::string ignored_err;
    if (this->post_json_(url, "{}", this->auth_token_, response, ignored_err)) {
      int sc = -1;
      std::string msg;
      cJSON *root = parse_envelope(response, sc, msg);
      if (root != nullptr && sc == 100) {
        cJSON *body_obj = cJSON_GetObjectItemCaseSensitive(root, "body");
        cJSON *r = body_obj ? cJSON_GetObjectItemCaseSensitive(body_obj, "botRegion") : nullptr;
        if (cJSON_IsString(r) && r->valuestring && r->valuestring[0] != '\0') {
          this->region_ = r->valuestring;
        }
      }
      if (root != nullptr) cJSON_Delete(root);
    }
  }

  ESP_LOGI(TAG, "Logged in, region=%s", this->region_.c_str());
  return true;
}

bool CloudClient::list_keypads(std::vector<AccountKeypad> &out_keypads,
                               std::string &error_out, bool force_refresh) {
  if (!this->is_logged_in()) {
    error_out = "Not logged in";
    return false;
  }
  if (!force_refresh && !this->keypads_cache_.empty()) {
    out_keypads = this->keypads_cache_;
    return true;
  }

  std::string url = this->wonderlabs_base_() + "/wonder/device/v3/getdevice";
  std::string response;
  if (!this->post_json_(url, R"json({"required_type":"All"})json",
                        this->auth_token_, response, error_out)) {
    return false;
  }

  int sc = -1;
  std::string msg;
  cJSON *root = parse_envelope(response, sc, msg);
  if (root == nullptr) {
    error_out = "Device list response was not valid JSON";
    return false;
  }
  if (sc != 100) {
    error_out = msg.empty() ? "Device list rejected" : msg;
    cJSON_Delete(root);
    return false;
  }

  cJSON *body_obj = cJSON_GetObjectItemCaseSensitive(root, "body");
  cJSON *items = body_obj ? cJSON_GetObjectItemCaseSensitive(body_obj, "Items") : nullptr;
  if (!cJSON_IsArray(items)) {
    error_out = "Device list missing Items array";
    cJSON_Delete(root);
    return false;
  }

  // Return every account device that has a MAC. We don't classify here — the
  // pairing UI decides which of these are keypads purely from each device's
  // live BLE advertisement (see keypad_advert.h).
  std::vector<AccountKeypad> picked;
  cJSON *item = nullptr;
  cJSON_ArrayForEach(item, items) {
    cJSON *mac = cJSON_GetObjectItemCaseSensitive(item, "device_mac");
    if (!cJSON_IsString(mac) || mac->valuestring == nullptr) continue;
    cJSON *name = cJSON_GetObjectItemCaseSensitive(item, "device_name");

    AccountKeypad kp;
    kp.mac          = compact_mac(mac->valuestring);
    kp.mac_pretty   = pretty_mac(kp.mac);
    kp.name         = (cJSON_IsString(name) && name->valuestring) ? name->valuestring
                                                                   : kp.mac_pretty;
    picked.push_back(std::move(kp));
  }
  cJSON_Delete(root);

  ESP_LOGI(TAG, "Account has %u device(s)", static_cast<unsigned>(picked.size()));

  this->keypads_cache_ = picked;
  out_keypads = std::move(picked);
  return true;
}

bool CloudClient::fetch_keypad_key(const std::string &mac,
                                   std::string &key_id_hex,
                                   std::vector<uint8_t> &key_bytes,
                                   std::string &error_out) {
  if (!this->is_logged_in()) {
    error_out = "Not logged in";
    return false;
  }

  std::string url = this->wonderlabs_base_() + "/wonder/keys/v1/communicate";
  std::string body;
  body.reserve(64);
  body += R"json({"device_mac":")json";
  body += compact_mac(mac);
  body += R"json(","keyType":"user"})json";

  std::string response;
  if (!this->post_json_(url, body, this->auth_token_, response, error_out)) {
    return false;
  }

  int sc = -1;
  std::string msg;
  cJSON *root = parse_envelope(response, sc, msg);
  if (root == nullptr) {
    error_out = "communicate response was not valid JSON";
    return false;
  }
  if (sc != 100) {
    error_out = msg.empty() ? "communicate rejected" : msg;
    cJSON_Delete(root);
    return false;
  }

  cJSON *body_obj = cJSON_GetObjectItemCaseSensitive(root, "body");
  cJSON *ckey = body_obj ? cJSON_GetObjectItemCaseSensitive(body_obj, "communicationKey") : nullptr;
  if (!cJSON_IsObject(ckey)) {
    error_out = "communicate response missing communicationKey";
    cJSON_Delete(root);
    return false;
  }
  cJSON *kid = cJSON_GetObjectItemCaseSensitive(ckey, "keyId");
  cJSON *k   = cJSON_GetObjectItemCaseSensitive(ckey, "key");
  if (!cJSON_IsString(kid) || !cJSON_IsString(k) ||
      kid->valuestring == nullptr || k->valuestring == nullptr) {
    error_out = "communicate response missing keyId/key";
    cJSON_Delete(root);
    return false;
  }

  key_id_hex = kid->valuestring;
  if (!parse_hex_string(k->valuestring, key_bytes) || key_bytes.size() != 16) {
    error_out = "communicate returned a malformed AES key";
    cJSON_Delete(root);
    return false;
  }
  cJSON_Delete(root);
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
