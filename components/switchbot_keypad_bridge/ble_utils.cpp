#include "ble_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv) {
  static const NimBLEUUID U_FD3D(static_cast<uint16_t>(0xFD3D));
  static const NimBLEUUID U_0D00(static_cast<uint16_t>(0x0D00));
  std::string sd = adv->getServiceData(U_FD3D);
  if (sd.empty()) sd = adv->getServiceData(U_0D00);
  return std::vector<uint8_t>(sd.begin(), sd.end());
}

std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr) {
  std::array<uint8_t, 6> out{};
  const uint8_t *raw = addr.getBase()->val;  // little-endian
  for (size_t i = 0; i < 6; ++i) {
    out[i] = raw[5 - i];
  }
  return out;
}

void configure_switchbot_scan(NimBLEScan *scan) {
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(30);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
