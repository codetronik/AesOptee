#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdio.h>
#include "../include/common.h"

void logHex(const unsigned char* hex, size_t size)
{
    char line[49];
    int index = 0;

    for (size_t i = 0; i < size; i++)
	{
        snprintf(line + index, sizeof(line) - index, "%02hhx ", hex[i]);
        index += 3;

        if ((i + 1) % 16 == 0 || i == size - 1)
		{
            line[index] = '\0'; 
            printf("%s\n", line);
            index = 0;
        }
    }
}

bool saveKey(const char* alias, unsigned char* key)
{
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_Result res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					alias, strlen(alias),
					TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE,
					TEE_HANDLE_NULL,
					NULL, 0,
					&object);

	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		return false;
	}

	res = TEE_WriteObjectData(object, key, 16);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
		return false;
	} 

	TEE_CloseObject(object);

	return true;
}

TEE_Result loadKey(const char* alias, unsigned char* key)
{
	TEE_Result res;
	
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					alias, strlen(alias),
					TEE_DATA_FLAG_ACCESS_READ |	TEE_DATA_FLAG_SHARE_READ,
					&object);

	if (res == TEE_ERROR_ITEM_NOT_FOUND)
	{
		goto EXIT;
	}

	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
		goto EXIT_ERROR;
	}

	TEE_ObjectInfo objectInfo;
	res = TEE_GetObjectInfo1(object, &objectInfo);
	if (res != TEE_SUCCESS)
	 {
		EMSG("TEE_GetObjectInfo1 failed 0x%08x", res);
		goto EXIT_ERROR;
	}

	uint32_t readBytes;
	res = TEE_ReadObjectData(object, key, objectInfo.dataSize, &readBytes);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_ReadObjectData failed 0x%08x", res);
		goto EXIT_ERROR;
	}

EXIT:
EXIT_ERROR:
	if (object != TEE_HANDLE_NULL)
	{
		TEE_CloseObject(object);
	}

	return res;
}


bool setOperation(TEE_OperationHandle* opHandle, unsigned char* key, TEE_OperationMode opMode)
{	
	bool success = false;
	TEE_ObjectHandle keyHandle = TEE_HANDLE_NULL;

	// 오퍼레이션 할당
	TEE_Result res = TEE_AllocateOperation(opHandle, TEE_ALG_AES_GCM, opMode, 128);
	if (res != TEE_SUCCESS)
	 {
		EMSG("TEE_AllocateOperation failed 0x%08x", res);
		goto EXIT_ERROR;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &keyHandle);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_AllocateTransientObject failed 0x%08x", res);
		goto EXIT_ERROR;
	}

	TEE_Attribute attr;
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, 16);

	res = TEE_PopulateTransientObject(keyHandle, &attr, 1);
	if (res != TEE_SUCCESS)
	 {
		EMSG("TEE_PopulateTransientObject failed 0x%08x", res);
		goto EXIT_ERROR;
	}

	res = TEE_SetOperationKey(*opHandle, keyHandle);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_SetOperationKey failed 0x%08x", res);
		goto EXIT_ERROR;
	}
	success = true;

EXIT_ERROR:
	TEE_FreeTransientObject(keyHandle);

	return success;
}

bool decrypt(TEE_Param params[4], TEE_OperationHandle opHandle)
{
    bool success = false;
    TEE_Result res;

    DecryptParams* dParams = (DecryptParams*)params[0].memref.buffer;

    size_t cipherSize = dParams->cipherSize;
    size_t ivSize = dParams->ivSize;
    size_t aadSize = dParams->aadSize;
    size_t tagSize = dParams->tagSize;

    unsigned char* cipher = dParams->buffer;
    unsigned char* iv = dParams->buffer + cipherSize;
    unsigned char* aad = dParams->buffer + cipherSize + ivSize;
    unsigned char* tag = dParams->buffer + cipherSize + ivSize + aadSize;

    //logHex(iv, ivSize);

    res = TEE_AEInit(opHandle, iv, ivSize, 128, aadSize, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_AEInit failed 0x%08x", res);
        return false;
    }

    // AAD 추가
    TEE_AEUpdateAAD(opHandle, aad, aadSize);

    // 복호화 수행
    uint32_t plainLen = cipherSize;
    res = TEE_AEDecryptFinal(opHandle, cipher, cipherSize, params[1].memref.buffer, &plainLen, tag, tagSize);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_AEDecryptFinal failed 0x%08x", res);
        return false;
    }

    logHex(params[1].memref.buffer, plainLen);

    return true;
}


bool encrypt(TEE_Param params[4], TEE_OperationHandle opHandle)
{
	TEE_Result res;

	EncryptParams *eParams = (EncryptParams *)params[0].memref.buffer;

    size_t plainSize = eParams->plainSize;
    size_t aadSize = eParams->aadSize;

	unsigned char *plain = eParams->buffer;
	unsigned char *aad = eParams->buffer + plainSize;

	// IV 랜덤 생성
	unsigned char iv[12] = {0, };
	TEE_GenerateRandom(iv, 12);
	logHex(iv, 12);

	res = TEE_AEInit(opHandle, iv, 12, 128, aadSize, 0);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_AEInit failed 0x08%x", res);
		return false;
	}
	
	// AAD 추가
	TEE_AEUpdateAAD(opHandle, aad, aadSize);

	// 암호화 수행
    uint32_t tagLen = 16; // 길이 지정 필수
	uint32_t cipherLen = plainSize;
 	res = TEE_AEEncryptFinal(opHandle, plain, plainSize, params[1].memref.buffer, &cipherLen, params[3].memref.buffer, &tagLen);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_AEEncryptFinal failed 0x%08x", res);
		return false;
	}

	memcpy(params[2].memref.buffer, iv, 12); 	// iv
	logHex(params[3].memref.buffer, 16); 		// tag
	logHex(params[1].memref.buffer, cipherLen); // cipher
	
	return true;
}


TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused paramTypes, TEE_Param __unused params[4], void __unused **session)
{		
	// 세션에 key 공간 할당
	*session = TEE_Malloc(16, 0);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *key)
{
	TEE_Free(key);
}

TEE_Result TA_InvokeCommandEntryPoint(void *key, uint32_t commandID, uint32_t __maybe_unused paramTypes, TEE_Param params[4])
{
	if (commandID == TA_CMD_GENERATE_KEY)
	{
		// alias 할당
		char* alias = TEE_Malloc(params[0].memref.size, 0);
		TEE_MemMove(alias, params[0].memref.buffer, params[0].memref.size);

		// key 할당
		unsigned char key_[16];
		TEE_GenerateRandom(key_, 16);
		logHex(key_, 16);
		TEE_MemMove(key, key_, 16);

		// key 저장
		bool success = saveKey(alias, key); 

		TEE_Free(alias);

		return success ? TEE_SUCCESS : TEE_ERROR_GENERIC;
	}
	else if (commandID == TA_CMD_LOAD_KEY)
	{
		// alias 할당
		char* alias = TEE_Malloc(params[0].memref.size, 0);
		TEE_MemMove(alias, params[0].memref.buffer, params[0].memref.size);

		TEE_Result res = loadKey(alias, key);
		logHex(key, 16);
		TEE_Free(alias);

		return res;
	}
	else if (commandID == TA_CMD_AES_ENCRYPT)
	{	
		TEE_OperationHandle opHandle = TEE_HANDLE_NULL;
		bool success = setOperation(&opHandle, key, TEE_MODE_ENCRYPT);
		if (success == false)
		{
			if (opHandle != TEE_HANDLE_NULL) TEE_FreeOperation(opHandle);
			return TEE_ERROR_GENERIC;
		}

		success = encrypt(params, opHandle);
		if (success == false)
		{
			TEE_FreeOperation(opHandle);
			return TEE_ERROR_GENERIC;
		}

		TEE_FreeOperation(opHandle);
		return TEE_SUCCESS;
	}
	else if (commandID == TA_CMD_AES_DECRYPT)
	{	
		TEE_OperationHandle opHandle = TEE_HANDLE_NULL;
		bool success = setOperation(&opHandle, key, TEE_MODE_DECRYPT);
		if (success == false)
		{
			if (opHandle != TEE_HANDLE_NULL) TEE_FreeOperation(opHandle);
			return TEE_ERROR_GENERIC;
		}

		success = decrypt(params, opHandle);
		if (success == false)
		{
			TEE_FreeOperation(opHandle);
			return TEE_ERROR_GENERIC;
		}

		TEE_FreeOperation(opHandle);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}