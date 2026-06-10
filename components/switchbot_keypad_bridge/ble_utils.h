#pragma once

// Small NimBLE helpers shared by the bridge, the pairer and the pairing UI.
//
// keypad_advert.h is deliberately NimBLE-free; everything here is the glue
// between NimBLE types and that raw-bytes world (service-data extraction,
// address formats, common scan parameters).

#include <NimBLEDevice.h>

// NimBLE leaks LOG_LEVEL_* macros that collide with ESPHome's enum.
#undef LOG_LEVEL_NONE
#undef LOG_LEVEL_ERROR
#undef LOG_LEVEL_WARN
#undef LOG_LEVEL_INFO
#undef LOG_LEVEL_DEBUG
#undef LOG_LEVEL_CRITICAL

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome {
namespace switchbot_keypad_bridge {

// Read the SwitchBot service-data blob from an advertisement (UUID 0xFD3D,
// with the legacy 0x0D00 as a fallback). Empty when not present.
std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv);

// Upper-cased copy of a MAC string, for case-insensitive comparisons
// ("b0:e9:fe:…" → "B0:E9:FE:…").
std::string upper_mac(std::string mac);

// Address bytes in big-endian (printed) order — NimBLE stores them reversed.
std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr);

// Parse "B0:E9:FE:11:22:33" (any case) into 6 big-endian bytes.
bool parse_mac_pretty(const std::string &mac, uint8_t out[6]);

// Apply the scan parameters every SwitchBot scan in this project uses, and
// drop any previous results. Active scanning is required — the keypad's
// 0xFD3D service data rides in the scan response.
void configure_switchbot_scan(NimBLEScan *scan);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
