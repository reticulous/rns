/* Host stand-in for ESP-IDF's hardware RNG. The record path does not use it —
 * only the sync beat's jitter does — so a deterministic value is what a test
 * wants anyway: a run that varies with entropy cannot be compared with the
 * previous one. */
#pragma once
#include <cstdint>
inline uint32_t esp_random() { return 0; }
