#pragma once
#include <iostream>
#include <err.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <tee_client_api.h>
#include <vector>
#include <array>
#include <optional>
#include "../include/common.h"

struct EncryptData
{
	std::vector<unsigned char> cipher;
	std::array<unsigned char, 12> iv;
	std::array<unsigned char, 16> tag;
};
 
class TeeAes
{
public:
	TeeAes()
	{

	}
	virtual ~TeeAes()
	{
		TEEC_CloseSession(&session);
		TEEC_FinalizeContext(&ctx);
	}
	
	std::optional<std::vector<unsigned char>> decrypt(
		std::vector<unsigned char> cipher, 
		std::array<unsigned char, 12> iv, 
		std::vector<unsigned char> aad, 
		std::array<unsigned char, 16> tag)
	{
		TEEC_SharedMemory in;
	
		// 공유 메모리 생성
		size_t cipherSize = cipher.size();
		size_t ivSize = iv.size();
		size_t aadSize = aad.size();
		size_t tagSize = tag.size();
	
		in.size = sizeof(DecryptParams) + cipherSize + ivSize + aadSize + tagSize;
		in.flags = TEEC_MEM_INPUT;
	
		TEEC_Result res = TEEC_AllocateSharedMemory(&ctx, &in);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "TEEC_AllocateSharedMemory failed 0x%x", res);
			return std::nullopt;
		}
	
		// 데이터 복사
		DecryptParams* params = (DecryptParams*)in.buffer;
		params->cipherSize = cipherSize;
		params->ivSize = ivSize;
		params->aadSize = aadSize;
		params->tagSize = tagSize;
	
		memcpy(params->buffer, cipher.data(), cipherSize);
		memcpy(params->buffer + cipherSize, iv.data(), ivSize);
		memcpy(params->buffer + cipherSize + ivSize, aad.data(), aadSize);
		memcpy(params->buffer + cipherSize + ivSize + aadSize, tag.data(), tagSize);
	
		std::vector<unsigned char> plain;
		plain.resize(cipherSize);
	
		TEEC_Operation op = { 0, };
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
		
		op.params[0].memref.parent = &in;
		op.params[1].tmpref.buffer = plain.data();
		op.params[1].tmpref.size = cipherSize;
	
		uint32_t origin;
		res = TEEC_InvokeCommand(&session, TA_CMD_AES_DECRYPT, &op, &origin);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "TEEC_InvokeCommand failed 0x%x origin 0x%x", res, origin);
			TEEC_ReleaseSharedMemory(&in);
			return std::nullopt;
		}
	
		TEEC_ReleaseSharedMemory(&in);
		return plain;
	}
	

	std::optional<EncryptData> encrypt(std::vector<unsigned char> plain, std::vector<unsigned char> aad)
	{
		TEEC_SharedMemory in;

		// 공유 메모리 생성
		size_t plainSize = plain.size();
		size_t aadSize = aad.size();
		in.size = sizeof(EncryptParams) + plainSize + aadSize;
		in.flags = TEEC_MEM_INPUT;
		TEEC_Result res = TEEC_AllocateSharedMemory(&ctx, &in);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "TEEC_AllocateSharedMemory failed 0x%x", res);
			return std::nullopt;
		}

		// 데이터 복사
		EncryptParams *params = (EncryptParams *)in.buffer;
		params->plainSize = plainSize;
		params->aadSize = aadSize;

		memcpy(params->buffer, plain.data(), plainSize);
		memcpy(params->buffer + plainSize, aad.data(), aadSize);

		std::vector<unsigned char> cipher;
		cipher.resize(plain.size());
		std::array<unsigned char, 12> iv;
		std::array<unsigned char, 16> tag;

		TEEC_Operation op = { 0, };
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
		op.params[0].memref.parent = &in;
		op.params[1].tmpref.buffer = cipher.data();
		op.params[1].tmpref.size = plain.size();
		op.params[2].tmpref.buffer = iv.data();
		op.params[2].tmpref.size = 12;
		op.params[3].tmpref.buffer = tag.data();
		op.params[3].tmpref.size = 16;

		uint32_t origin;
		res = TEEC_InvokeCommand(&session, TA_CMD_AES_ENCRYPT, &op, &origin);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "TEEC_InvokeCommand failed 0x%x origin 0x%x", res, origin);
			TEEC_ReleaseSharedMemory(&in);
			return std::nullopt;
		}

		TEEC_ReleaseSharedMemory(&in);

		EncryptData encData;
		encData.cipher = cipher;
		encData.iv = iv;
		encData.tag = tag;

		return encData;
	}

	bool generateKey(std::string alias)
	{
		TEEC_Operation op = { 0, };
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = alias.data();
		op.params[0].tmpref.size = alias.size();

		uint32_t origin;
		TEEC_Result res = TEEC_InvokeCommand(&session, TA_CMD_GENERATE_KEY, &op, &origin);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "generateKey : TEEC_InvokeCommand failed 0x%x origin 0x%x", res, origin);
			return false;
		}

		return true;
	}

	TEEC_Result loadKey(std::string alias)
	{
		TEEC_Operation op = { 0, };
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = alias.data();
		op.params[0].tmpref.size = alias.size();

		uint32_t origin;
		TEEC_Result res = TEEC_InvokeCommand(&session, TA_CMD_LOAD_KEY, &op, &origin);
		if (res == TEEC_ERROR_ITEM_NOT_FOUND)
		{

		}
		else if (res != TEEC_SUCCESS)
		{
			errx(1, "loadKey : TEEC_InvokeCommand failed 0x%x origin 0x%x", res, origin);	
		}

		return res;
	}

	bool init()
	{		
		TEEC_Result res = TEEC_InitializeContext(NULL, &ctx);
		if (res != TEEC_SUCCESS)
		{
			errx(1, "result %x", res);
			return false;
		}		
		
		TEEC_UUID uuid = TA_AES_EXAMPLE_UUID;
		uint32_t errOrigin;
	
		res = TEEC_OpenSession(&ctx, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &errOrigin);
		if (res != TEEC_SUCCESS) 
		{
			errx(1, "result %x / error %x", res, errOrigin);
			return false;
		}

		return true;
	}

	bool loadOrGenKey(std::string alias)
	{
		bool needGenerateKey = false;
		TEEC_Result res = loadKey(alias);
		if (res == TEEC_ERROR_ITEM_NOT_FOUND)
		{
			printf("key not found!\n");	
			needGenerateKey = true;
		} 
		else if (res != TEEC_SUCCESS)
		{
			errx(1, "loadKey failed");
			return false;
		}
		else 
		{
			printf("loadKey success\n");
		}
		
		if (needGenerateKey == true)
		{
			bool success = generateKey(alias);
			if (success == false)
			{
				printf("generateKey failed\n");
				return false;
			}
			else
			{
				printf("generateKey success\n");
			}
		}

		return true;
	}

private:
	TEEC_Context ctx;
	TEEC_Session session;
};