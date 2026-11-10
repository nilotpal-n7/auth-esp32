// =============================================================================
// core/mem.h — how much RAM is really left
//
// ESP.getFreeHeap() / getMaxAllocHeap() also count ~12 KB of spare
// instruction RAM (IRAM) that malloc(), new and String can never use, so they
// report "largest block 11 KB" even when the usable heap is exhausted. These
// report the heap that ordinary allocations come from.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace mem {

void     init();              // call first in setup(): counts failed allocations
uint32_t freeHeap();          // usable free heap, bytes
uint32_t largestBlock();      // largest single allocation possible now
uint32_t minFreeHeap();       // lowest freeHeap() since boot
uint32_t failures();          // allocations that failed since boot
uint32_t lastFailedSize();    // size of the latest one
bool     roomForTls();        // enough for one more TLS handshake (config.h: TLS_MIN_*)

}  // namespace mem
