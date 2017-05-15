/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
/* http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c */
#include <stdint.h>
#include "base64.h"

static unsigned char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/* URL ENCODING VARIANT               = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" */
static unsigned char decoding_table[256];
static int mod_table[] = {0, 2, 1};

static inline void build_base64_table() {
	int i;
	for (i = 0; i < 64; i++)
		decoding_table[encoding_table[i]] = i;
	
	/* URL encoding variant */
	decoding_table['-'] = decoding_table['+'];
	decoding_table['_'] = decoding_table['/'];
}

sds base64_encode(const unsigned char *data, size_t input_length)
{
	int i,j;
	size_t output_length;
	sds temp,encoded_data;
	
	output_length = 4 * ((input_length + 2) / 3);
	
	temp = sdsempty();
	if (!temp) return (sds)0;
	
	encoded_data = sdsgrowzero(temp,output_length);
	if (!encoded_data){ sdsfree(temp); return (sds)0; }
	
	for (i = 0, j = 0; i < input_length;) {
		uint32_t octet_a = i < input_length ? data[i++] : 0;
		uint32_t octet_b = i < input_length ? data[i++] : 0;
		uint32_t octet_c = i < input_length ? data[i++] : 0;
		
		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
		
		encoded_data[j++] = encoding_table[(triple >> (3 * 6)) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> (2 * 6)) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> (1 * 6)) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> (0 * 6)) & 0x3F];
	}
	for (i = 0,j = mod_table[input_length % 3]; i < j; i++)
		encoded_data[--output_length] = '=';
	
	return encoded_data;
}


sds base64_decode(const unsigned char *data, size_t input_length)
{
	int i,j;
	size_t output_length;
	sds temp,decoded_data;

	if (!decoding_table['_']) build_base64_table();

	if (input_length % 4 != 0) return (sds)0;

	output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') output_length--;
	if (data[input_length - 2] == '=') output_length--;

	temp = sdsempty();
	if (!temp) return (sds)0;
	
	decoded_data = sdsgrowzero(temp,output_length);
	if (!decoded_data) { sdsfree(temp); return (sds)0; }
	
	for (i = 0, j = 0; i < input_length;) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		
		uint32_t triple
			= (sextet_a << (3 * 6))
			+ (sextet_b << (2 * 6))
			+ (sextet_c << (1 * 6))
			+ (sextet_d << (0 * 6));
		
		if (j < output_length) decoded_data[j++] = (triple >> (2 * 8)) & 0xFF;
		if (j < output_length) decoded_data[j++] = (triple >> (1 * 8)) & 0xFF;
		if (j < output_length) decoded_data[j++] = (triple >> (0 * 8)) & 0xFF;
	}
	return decoded_data;
}

