#include "Base64Function.h"

std::string base64Encode(const unsigned char* buffer, size_t bufferSize) {
	std::string encoded;

	size_t i = 0;

	while (i < bufferSize) {
		unsigned char char1 = buffer[i++];
		unsigned char char2 = (i < bufferSize) ? buffer[i++] : 0;
		unsigned char char3 = (i < bufferSize) ? buffer[i++] : 0;

		unsigned char enc1 = char1 >> 2;
		unsigned char enc2 = ((char1 & 0x03) << 4) | (char2 >> 4);
		unsigned char enc3 = ((char2 & 0x0F) << 2) | (char3 >> 6);
		unsigned char enc4 = char3 & 0x3F;

		encoded += base64Chars[enc1];
		encoded += base64Chars[enc2];
		encoded += (char2 ? base64Chars[enc3] : '=');
		encoded += (char3 ? base64Chars[enc4] : '=');
	}

	return encoded;
}