#include "core/mem.h"
#include "config.h"

#include <esp_heap_caps.h>

namespace mem {

static volatile uint32_t s_failures = 0;
static volatile uint32_t s_lastSize = 0;

// Runs inside the failing allocation (any task): only count.
static void onAllocFailed(size_t size, uint32_t caps, const char*) {
    if (!(caps & MALLOC_CAP_DEFAULT) && !(caps & MALLOC_CAP_8BIT)) return;
    s_failures++;
    s_lastSize = size;
}

void init() { heap_caps_register_failed_alloc_callback(onAllocFailed); }

uint32_t freeHeap()       { return heap_caps_get_free_size(MALLOC_CAP_DEFAULT); }
uint32_t largestBlock()   { return heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT); }
uint32_t minFreeHeap()    { return heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT); }
uint32_t failures()       { return s_failures; }
uint32_t lastFailedSize() { return s_lastSize; }
bool     roomForTls()     { return freeHeap() >= TLS_MIN_FREE_HEAP && largestBlock() >= TLS_MIN_BLOCK; }

}  // namespace mem
