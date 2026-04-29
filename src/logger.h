#pragma once

#include <Arduino.h>

#define LOG_BUFFER_SIZE 10
#define LOG_MAX_LENGTH  32

// Initialize the logger
void loggerInit();

// Add a log message to the circular buffer
void logAdd(const char* format, ...);

// Get the number of logs currently in the buffer (max LOG_BUFFER_SIZE)
int logGetCount();

// Get a log string by index. Index 0 is the oldest log, index (count-1) is the newest.
const char* logGetMessage(int index);
