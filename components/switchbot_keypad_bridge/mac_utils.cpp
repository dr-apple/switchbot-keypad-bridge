#include "mac_utils.h"

#include <cctype>
#include <cstdio>

namespace esphome {
namespace switchbot_keypad_bridge {

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

std::string pretty_mac(const std::string &raw) {
  const std::string compact = compact_mac(raw);
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

std::string upper_mac(std::string mac) {
  for (auto &c : mac) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return mac;
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

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
