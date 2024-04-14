#pragma once
#include "headers.h"
const std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


std::string base64Encode(const unsigned char* buffer, size_t bufferSize);