#include "pairing_ui.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include "esphome/core/log.h"
#include "keypad_advert.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {
const char *const TAG = "switchbot_keypad_bridge.ui";

// Helpers to register a URI with the user_ctx set to a PairingUi instance.
httpd_uri_t make_uri(const char *path, httpd_method_t method,
                     esp_err_t (*handler)(httpd_req_t *), void *ctx) {
  httpd_uri_t u{};
  u.uri = path;
  u.method = method;
  u.handler = handler;
  u.user_ctx = ctx;
  return u;
}
}  // namespace

// ── Lifecycle ─────────────────────────────────────────────────────────────

bool PairingUi::start(uint16_t port) {
  if (this->server_ != nullptr) {
    return true;
  }
  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.server_port = port;
  cfg.max_uri_handlers = 8;
  cfg.uri_match_fn = httpd_uri_match_wildcard;
  cfg.stack_size = 8192;  // headroom for the BLE scan run from /api/keypads
  cfg.lru_purge_enable = true;

  if (httpd_start(&this->server_, &cfg) != ESP_OK) {
    ESP_LOGE(TAG, "httpd_start failed on port %u", port);
    this->server_ = nullptr;
    return false;
  }

  auto reg = [this](const char *path, httpd_method_t m,
                    esp_err_t (*h)(httpd_req_t *)) {
    httpd_uri_t u = make_uri(path, m, h, this);
    httpd_register_uri_handler(this->server_, &u);
  };
  reg("/",                  HTTP_GET,  PairingUi::handle_root_);
  reg("/api/login",         HTTP_POST, PairingUi::handle_login_);
  reg("/api/keypads",       HTTP_GET,  PairingUi::handle_keypads_);
  reg("/api/pair",          HTTP_POST, PairingUi::handle_pair_);
  reg("/api/pair/status",   HTTP_GET,  PairingUi::handle_pair_status_);

  ESP_LOGI(TAG, "Pairing UI listening on http://<device>:%u/", port);
  return true;
}

void PairingUi::stop() {
  if (this->server_ != nullptr) {
    httpd_stop(this->server_);
    this->server_ = nullptr;
  }
}

// ── URI handlers ──────────────────────────────────────────────────────────

esp_err_t PairingUi::handle_root_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  if (self->html_ == nullptr || self->html_len_ == 0) {
    return reply_error_(req, "500 Internal Server Error",
                        "Pairing UI was not embedded in this build.");
  }
  httpd_resp_set_type(req, "text/html; charset=utf-8");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  return httpd_resp_send(req, reinterpret_cast<const char *>(self->html_),
                         static_cast<ssize_t>(self->html_len_));
}

namespace {

// Minimal escaper for the JSON strings we emit. Handles the cases we
// realistically see (quotes and backslashes inside device names).
std::string json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

// Pull a top-level JSON string property out of a request body. Returns
// empty on missing/malformed. Tiny hand-rolled extractor — we only need
// it for two fields and don't want to pull cJSON into the request path.
std::string extract_json_str(const std::string &body, const char *key) {
  std::string needle = std::string("\"") + key + "\"";
  size_t k = body.find(needle);
  if (k == std::string::npos) return "";
  size_t colon = body.find(':', k);
  if (colon == std::string::npos) return "";
  size_t open = body.find('"', colon);
  if (open == std::string::npos) return "";
  ++open;
  std::string out;
  while (open < body.size() && body[open] != '"') {
    if (body[open] == '\\' && open + 1 < body.size()) {
      char esc = body[open + 1];
      switch (esc) {
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default:  out.push_back(esc);
      }
      open += 2;
    } else {
      out.push_back(body[open++]);
    }
  }
  return out;
}

// One nearby BLE device: strongest RSSI seen plus its SwitchBot service-data
// blob (so the UI can identify the keypad model the pySwitchbot way).
struct NearbyDevice {
  int rssi{0};
  std::vector<uint8_t> svc_data;
};

// Read the SwitchBot service-data blob from an advertisement (UUID 0xFD3D,
// with the legacy 0x0D00 as a fallback). Empty when not present.
std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv) {
  static const NimBLEUUID U_FD3D(static_cast<uint16_t>(0xFD3D));
  static const NimBLEUUID U_0D00(static_cast<uint16_t>(0x0D00));
  std::string sd = adv->getServiceData(U_FD3D);
  if (sd.empty()) sd = adv->getServiceData(U_0D00);
  return std::vector<uint8_t>(sd.begin(), sd.end());
}

// Active-scan for `duration_ms` and record, for each advertising address
// (upper-case, colon-separated), the strongest RSSI and its SwitchBot service
// data. Lets the UI flag which account keypads are reachable right now and
// identify their model straight from the advertisement.
std::map<std::string, NearbyDevice> scan_nearby(uint32_t duration_ms) {
  std::map<std::string, NearbyDevice> seen;
  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(30);

  NimBLEScanResults results = scan->getResults(duration_ms, false);
  for (int i = 0; i < results.getCount(); ++i) {
    const NimBLEAdvertisedDevice *adv = results.getDevice(i);
    std::string mac = adv->getAddress().toString();
    for (auto &c : mac) {
      if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    const int rssi = adv->getRSSI();
    auto it = seen.find(mac);
    if (it == seen.end() || rssi > it->second.rssi) {
      NearbyDevice &dev = seen[mac];
      dev.rssi = rssi;
      std::vector<uint8_t> sd = switchbot_service_data(adv);
      if (!sd.empty()) dev.svc_data = std::move(sd);
    }
  }
  scan->clearResults();
  return seen;
}

}  // namespace

esp_err_t PairingUi::handle_login_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  std::string body = read_body_(req);
  std::string email    = extract_json_str(body, "email");
  std::string password = extract_json_str(body, "password");
  if (email.empty() || password.empty()) {
    return reply_error_(req, "400 Bad Request", "Missing email or password.");
  }
  ESP_LOGI(TAG, "POST /api/login email=%s", email.c_str());

  std::string err;
  if (!self->cloud_.login(email, password, err)) {
    ESP_LOGW(TAG, "Login failed: %s", err.c_str());
    return reply_error_(req, "401 Unauthorized", err);
  }
  std::string resp = R"json({"region":")json";
  resp += json_escape(self->cloud_.region());
  resp += R"json("})json";
  return reply_json_(req, resp.c_str());
}

esp_err_t PairingUi::handle_keypads_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  if (!self->cloud_.is_logged_in()) {
    return reply_error_(req, "401 Unauthorized", "Sign in first.");
  }
  std::vector<CloudClient::AccountKeypad> keypads;
  std::string err;
  if (!self->cloud_.list_keypads(keypads, err)) {
    ESP_LOGW(TAG, "list_keypads failed: %s", err.c_str());
    return reply_error_(req, "502 Bad Gateway", err);
  }

  // Cross-reference the account devices against a fresh BLE scan: this both
  // shows which ones are in range (and how strong the signal is) and identifies
  // the keypad model straight from the advertisement (pySwitchbot-style).
  const std::map<std::string, NearbyDevice> nearby = scan_nearby(4000);

  std::string out = "[";
  unsigned shown = 0;
  for (const auto &k : keypads) {
    const auto hit = nearby.find(k.mac_pretty);
    if (hit == nearby.end() || hit->second.svc_data.empty()) continue;

    // A device is a keypad only if its live advertisement matches a known
    // SwitchBot keypad signature. Everything else (locks, bots, hubs, …) and
    // any out-of-range device is skipped — detection is BLE-only.
    const KeypadIdent ident = identify_keypad(hit->second.svc_data.data(),
                                              hit->second.svc_data.size());
    if (!ident.is_keypad) continue;

    if (shown++ != 0) out += ",";
    out += R"json({"mac":")json";
    out += json_escape(k.mac_pretty);
    out += R"json(","name":")json";
    out += json_escape(k.name);
    out += R"json(","model":")json";
    out += json_escape(ident.display_name);
    out += R"json(","online":true,"rssi":)json";
    out += std::to_string(hit->second.rssi);
    out += "}";
  }
  out += "]";
  ESP_LOGI(TAG, "GET /api/keypads -> %u keypad(s) of %u account device(s), %u nearby",
           shown, static_cast<unsigned>(keypads.size()),
           static_cast<unsigned>(nearby.size()));
  return reply_json_(req, out.c_str());
}

namespace {

// Read the ESP's BLE peripheral address as a 6-byte big-endian array
// (MAC[0] is the leading byte). NimBLEAddress stores the bytes in
// little-endian internally so we reverse on the way out.
std::array<uint8_t, 6> esp_ble_mac() {
  std::array<uint8_t, 6> out{};
  const uint8_t *raw = NimBLEDevice::getAddress().getBase()->val;
  for (size_t i = 0; i < 6; ++i) {
    out[i] = raw[5 - i];
  }
  return out;
}

}  // namespace

esp_err_t PairingUi::handle_pair_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  std::string body = read_body_(req);
  std::string mac  = extract_json_str(body, "mac");
  if (mac.empty()) {
    return reply_error_(req, "400 Bad Request", "Missing keypad mac.");
  }
  ESP_LOGI(TAG, "POST /api/pair mac=%s", mac.c_str());

  if (!self->cloud_.is_logged_in()) {
    return reply_error_(req, "401 Unauthorized", "Sign in first.");
  }

  // Confirm the MAC belongs to this account (and grab its pretty form + name).
  // The protocol family is determined later by the pairer from the keypad's
  // live BLE advertisement.
  std::vector<CloudClient::AccountKeypad> keypads;
  std::string err;
  if (!self->cloud_.list_keypads(keypads, err)) {
    return reply_error_(req, "502 Bad Gateway", err);
  }
  const CloudClient::AccountKeypad *found = nullptr;
  for (const auto &kp : keypads) {
    if (kp.mac_pretty == mac || kp.mac == mac) {
      found = &kp;
      break;
    }
  }
  if (found == nullptr) {
    return reply_error_(req, "404 Not Found",
                        "Keypad not in this SwitchBot account.");
  }
  ESP_LOGI(TAG, "/api/pair matched keypad '%s' (%s)",
           found->name.c_str(), found->mac_pretty.c_str());

  // Fetch the keypad's current K14 from the SwitchBot cloud.
  std::string key_id_hex;
  std::vector<uint8_t> key_bytes;
  if (!self->cloud_.fetch_keypad_key(found->mac, key_id_hex, key_bytes, err)) {
    return reply_error_(req, "502 Bad Gateway", err);
  }

  // Build the pairer's request.
  KeypadPairer::Request kr;
  kr.keypad_mac  = found->mac_pretty;
  kr.key_id     = static_cast<int>(std::strtol(key_id_hex.c_str(), nullptr, 16));
  kr.key        = std::move(key_bytes);
  kr.shared_token = self->shared_key_;
  kr.esp_mac = esp_ble_mac();

  // Capture the name now — it belongs to this exact job.
  const std::string keypad_name = found->name;

  std::string job_id = self->pairer_.start(std::move(kr));
  if (job_id.empty()) {
    return reply_error_(req, "409 Conflict",
                        "A pairing job is already in progress.");
  }
  // Bind name + job id together, then arm the one-shot flag. start() has
  // already moved the job to RUNNING, so a status poll landing here can
  // no longer observe a previous job's lingering SUCCESS state.
  self->pairing_keypad_name_ = keypad_name;
  self->pairing_job_id_      = job_id;
  self->success_notified_    = false;
  std::string resp = R"json({"job_id":")json";
  resp += job_id;
  resp += R"json("})json";
  return reply_json_(req, resp.c_str());
}

esp_err_t PairingUi::handle_pair_status_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  KeypadPairer::Status st = self->pairer_.status();

  // Fire the paired callback exactly once, and only for the job this UI
  // actually started — matched by job id. This is what guarantees the
  // entity is renamed to the keypad just paired, never a previous one.
  if (st.state == KeypadPairer::State::SUCCESS && !self->success_notified_ &&
      st.job_id == self->pairing_job_id_ && !self->pairing_job_id_.empty()) {
    self->success_notified_ = true;
    if (self->on_paired_cb_) self->on_paired_cb_(self->pairing_keypad_name_);
  }

  bool done = st.state == KeypadPairer::State::SUCCESS ||
              st.state == KeypadPairer::State::FAILED;

  std::string resp = "{";
  resp += R"json("step":)json";
  resp += std::to_string(st.step);
  resp += R"json(,"total":)json";
  resp += std::to_string(st.total);
  resp += R"json(,"message":")json";
  resp += json_escape(st.message);
  resp += R"json(","done":)json";
  resp += done ? "true" : "false";
  resp += R"json(,"error":)json";
  if (st.state == KeypadPairer::State::FAILED) {
    resp += R"json(")json";
    resp += json_escape(st.error);
    resp += R"json(")json";
  } else {
    resp += "null";
  }
  resp += "}";
  return reply_json_(req, resp.c_str());
}

// ── Helpers ───────────────────────────────────────────────────────────────

esp_err_t PairingUi::reply_json_(httpd_req_t *req, const char *json,
                                 const char *status) {
  httpd_resp_set_status(req, status);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

esp_err_t PairingUi::reply_error_(httpd_req_t *req, const char *status,
                                  const std::string &message) {
  std::string body = R"json({"error":")json";
  for (char c : message) {
    if (c == '"' || c == '\\') body.push_back('\\');
    if (c == '\n' || c == '\r' || c == '\t') {
      body += "\\";
      body.push_back(c == '\n' ? 'n' : (c == '\r' ? 'r' : 't'));
    } else {
      body.push_back(c);
    }
  }
  body += R"json("})json";
  return reply_json_(req, body.c_str(), status);
}

std::string PairingUi::read_body_(httpd_req_t *req) {
  std::string buf;
  // Login / pair payloads are a few hundred bytes at most; refuse anything
  // larger so a bogus Content-Length cannot drive a huge heap allocation.
  constexpr size_t MAX_BODY_LEN = 2048;
  if (req->content_len == 0 || req->content_len > MAX_BODY_LEN) {
    return buf;
  }
  buf.resize(req->content_len);
  int received = httpd_req_recv(req, buf.data(),
                                static_cast<int>(req->content_len));
  if (received <= 0) {
    buf.clear();
  } else {
    buf.resize(received);
  }
  return buf;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
