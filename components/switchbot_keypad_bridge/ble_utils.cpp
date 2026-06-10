#include "ble_utils.h"

#include <cstdio>

namespace esphome {
namespace switchbot_keypad_bridge {

std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv) {
  static const NimBLEUUID U_FD3D(static_cast<uint16_t>(0xFD3D));
  static const NimBLEUUID U_0D00(static_cast<uint16_t>(0x0D00));
  std::string sd = adv->getServiceData(U_FD3D);
  if (sd.empty()) sd = adv->getServiceData(U_0D00);
  return std::vector<uint8_t>(sd.begin(), sd.end());
}

std::string upper_mac(std::string mac) {
  for (auto &c : mac) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return mac;
}

std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr) {
  std::array<uint8_t, 6> out{};
  const uint8_t *raw = addr.getBase()->val;  // little-endian
  for (size_t i = 0; i < 6; ++i) {
    out[i] = raw[5 - i];
  }
  return out;
}

bool parse_mac_pretty(const std::string &mac, uint8_t out[6]) {
  unsigned b[6];
  if (std::sscanf(mac.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x",
                  &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
    return false;
  }
  for (size_t i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(b[i]);
  return true;
}

void configure_switchbot_scan(NimBLEScan *scan) {
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(30);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
