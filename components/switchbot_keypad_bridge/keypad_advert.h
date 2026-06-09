#pragma once

// SwitchBot keypad identification from a BLE advertisement.
//
// This is the project's equivalent of pySwitchbot's `adv_parser` keypad
// detection: the model (and therefore the pairing protocol family) is read
// straight from the SwitchBot service-data advertisement rather than from a
// cloud SKU string. That makes detection independent of the ever-growing list
// of cloud `device_type` codes — a new keypad works as long as it advertises a
// recognised SwitchBot signature.
//
// The classifier is deliberately free of any NimBLE/cloud dependency: it takes
// the raw 0xFD3D service-data bytes so the byte-matching logic stays in one
// place and is trivial to reason about.

#include <cstddef>
#include <cstdint>

#include "cloud_client.h"

namespace esphome {
namespace switchbot_keypad_bridge {

struct KeypadIdent {
  bool is_keypad{false};
  CloudClient::KeypadFamily family{CloudClient::KeypadFamily::ORIGINAL};
  const char *display_name{"Keypad"};
};

// Identify a SwitchBot keypad from the bytes of its 0xFD3D service-data
// advertisement, mirroring pySwitchbot's SUPPORTED_TYPES signatures. Returns
// `is_keypad == false` when the advert is empty or not a recognised keypad.
KeypadIdent identify_keypad(const uint8_t *svc_data, size_t len);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
