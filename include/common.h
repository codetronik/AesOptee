#pragma once

typedef struct
{
    size_t plainSize;
    size_t aadSize;
	unsigned char buffer[]; 
} EncryptParams;

typedef struct
{
    size_t cipherSize;
    size_t ivSize;
    size_t aadSize;
    size_t tagSize;
	unsigned char buffer[]; 
} DecryptParams;

#define TA_AES_EXAMPLE_UUID	{ 0x11111111, 0x1111, 0x1111, { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } }

#define TA_CMD_GENERATE_KEY		0
#define TA_CMD_LOAD_KEY			1
#define TA_CMD_AES_ENCRYPT		2
#define TA_CMD_AES_DECRYPT		3