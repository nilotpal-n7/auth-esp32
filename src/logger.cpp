#include "logger.h"
#include <stdio.h>
#include <stdarg.h>

static char s_logBuffer[LOG_BUFFER_SIZE][LOG_MAX_LENGTH];
static int s_logHead = 0;
static int s_logCount = 0;

void loggerInit() {
    s_logHead = 0;
    s_logCount = 0;
}

void logAdd(const char* format, ...) {
    char temp[LOG_MAX_LENGTH];
    va_list args;
    va_start(args, format);
    vsnprintf(temp, sizeof(temp), format, args);
    va_end(args);

    // Also print to serial for debugging
    Serial.printf("[LOG] %s\n", temp);

    // Add to circular buffer
    snprintf(s_logBuffer[s_logHead], LOG_MAX_LENGTH, "%s", temp);
    
    s_logHead = (s_logHead + 1) % LOG_BUFFER_SIZE;
    if (s_logCount < LOG_BUFFER_SIZE) {
        s_logCount++;
    }
}

int logGetCount() {
    return s_logCount;
}

const char* logGetMessage(int index) {
    if (index < 0 || index >= s_logCount) {
        return "";
    }
    
    // Calculate the actual index in the circular buffer
    // Oldest item is at (head - count + size) % size
    int oldestIdx = (s_logHead - s_logCount + LOG_BUFFER_SIZE) % LOG_BUFFER_SIZE;
    int targetIdx = (oldestIdx + index) % LOG_BUFFER_SIZE;
    
    return s_logBuffer[targetIdx];
}
