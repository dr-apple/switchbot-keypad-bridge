#pragma once

// Small NimBLE helpers shared by the bridge, the pairer and the pairing UI.
//
// keypad_advert.h and mac_utils.h are deliberately NimBLE-free; everything
// here is the glue between NimBLE types and that raw-bytes world
// (service-data extraction, address bytes, common scan parameters).

#include "nimble_compat.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome {
namespace switchbot_keypad_bridge {

// Read the SwitchBot service-data blob from an advertisement (UUID 0xFD3D,
// with the legacy 0x0D00 as a fallback). Empty when not present.
std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv);

// Address bytes in big-endian (printed) order — NimBLE stores them reversed.
std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr);

// Apply the scan parameters every SwitchBot scan in this project uses, and
// drop any previous results. Active scanning is required — the keypad's
// 0xFD3D service data rides in the scan response.
void configure_switchbot_scan(NimBLEScan *scan);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
