#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "esphome/core/helpers.h"

namespace esphome {
namespace switchbot_keypad_bridge {

// ESPHome 2026.11 removed the std::string-returning format_hex_pretty(); only the
// buffer-based format_hex_pretty_to() is left (available on older versions too).
// This wrapper keeps the log call sites readable and builds on both.
inline std::string hex_pretty(const uint8_t *data, size_t length) {
  std::string out(format_hex_pretty_size(length) + 1, '\0');
  format_hex_pretty_to(&out[0], out.size(), data, length);
  out.resize(std::strlen(out.c_str()));
  return out;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
