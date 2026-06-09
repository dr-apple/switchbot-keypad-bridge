#include "keypad_advert.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

// pySwitchbot SUPPORTED_TYPES keypad signatures (SwitchBot service-data,
// advertised under UUID 0xFD3D — with 0x0D00 as a legacy fallback):
//
//   first byte 'y'  (0x79, low 7 bits) ........... Keypad / Keypad Touch → ORIGINAL
//   4-byte suffix  ?? 11 03 78  (?? = enc bit) .... Keypad Vision         → VISION
//   4-byte suffix  ?? 11 51 98 ................... Keypad Vision Pro      → VISION
//
// The first byte is matched after masking the high (encryption) bit; the
// Vision variants are matched as a trailing 4-byte window. This mirrors
// pySwitchbot's `_find_model_from_service_data` (first byte) and
// `_find_model_from_service_data_suffix` (which tries both the [-4:] and the
// [-5:-1] window).
constexpr uint8_t KEYPAD_TYPE_BYTE = 0x79;  // 'y'

// True when a 4-byte window equals `?? b1 b2 b3`, accepting 0x00 or 0x01 as the
// leading encryption bit (both forms appear in pySwitchbot's table).
bool suffix_is(const uint8_t *w, uint8_t b1, uint8_t b2, uint8_t b3) {
  return (w[0] == 0x00 || w[0] == 0x01) && w[1] == b1 && w[2] == b2 &&
         w[3] == b3;
}

}  // namespace

KeypadIdent identify_keypad(const uint8_t *svc_data, size_t len) {
  KeypadIdent id;
  if (svc_data == nullptr || len == 0) return id;

  // 1. First-byte match (low 7 bits) — Keypad / Keypad Touch (Original family).
  if ((svc_data[0] & 0x7F) == KEYPAD_TYPE_BYTE) {
    id.is_keypad = true;
    id.family = CloudClient::KeypadFamily::ORIGINAL;
    id.display_name = "Keypad";
    return id;
  }

  // 2. Trailing 4-byte window — Vision / Vision Pro (Vision family). Try both
  //    the last-4 and the next-to-last-4 windows, as pySwitchbot does.
  if (len > 5) {
    const uint8_t *windows[] = {svc_data + (len - 4), svc_data + (len - 5)};
    for (const uint8_t *w : windows) {
      if (suffix_is(w, 0x11, 0x03, 0x78)) {
        id.is_keypad = true;
        id.family = CloudClient::KeypadFamily::VISION;
        id.display_name = "Keypad Vision";
        return id;
      }
      if (suffix_is(w, 0x11, 0x51, 0x98)) {
        id.is_keypad = true;
        id.family = CloudClient::KeypadFamily::VISION;
        id.display_name = "Keypad Vision Pro";
        return id;
      }
    }
  }

  return id;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
