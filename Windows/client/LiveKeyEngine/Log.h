#pragma once

void logprintf(int level, const char* format, ...);

#define LOG_LEVEL_DISABLED  0
#define LOG_LEVEL_ERROR     1
#define LOG_LEVEL_INFO      2
#define LOG_LEVEL_DEBUG     3

#define LOG(level, fmt, ...) \
    logprintf(level, fmt, ##__VA_ARGS__)

// convenience wrappers
#define LOGE(fmt, ...) LOG(LOG_LEVEL_ERROR,  fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)


