#pragma once

// The component's single include point for NimBLE.
//
// NimBLE's log_common.h defines LOG_LEVEL_* as plain macros, which collide
// with identically-named members of ESPHome enums included downstream.
// ESPHome uses ESPHOME_LOG_LEVEL_* for its own logging, so undefining the
// macros right after the NimBLE headers is safe. Include this instead of
// <NimBLEDevice.h> so no header can forget the cleanup.

#include <NimBLEDevice.h>

#undef LOG_LEVEL_NONE
#undef LOG_LEVEL_ERROR
#undef LOG_LEVEL_WARN
#undef LOG_LEVEL_INFO
#undef LOG_LEVEL_DEBUG
#undef LOG_LEVEL_CRITICAL
