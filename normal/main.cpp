#include "TeeAes.h"
#include <iostream>

void logHex(unsigned char* hex, size_t size)
{
	std::string line;

	for (int i = 0; i < size; i++)
	{
		char temp[5] = { 0, };
		snprintf(temp, sizeof(temp), "%02hhx ", *(hex + i));
		line.append(temp);

		if ((i + 1) % 16 == 0 || i == size - 1)
		{
			printf("%s\n", line.c_str());
			line.clear();
		}
	}
}	

int main(void)
{
	// 암호화 테스트트
	TeeAes teeAesEncrypt;
	if (teeAesEncrypt.init() == false)
	{
		return 0;
	}

	if (teeAesEncrypt.loadOrGenKey("alias0001") == false)
	{
		return 0;
	}	

	std::string str = "hello";
	std::vector<unsigned char> plain(str.begin(), str.end());

	std::string str2 = "world";
	std::vector<unsigned char> aad(str2.begin(), str2.end());

	auto encData = teeAesEncrypt.encrypt(plain, aad);
	if (encData.has_value() == false)
	{
		printf("encrypt failed\n");
		return 0;
	}

	printf("cipher\n");
	logHex(encData.value().cipher.data(), str.size());
	printf("iv\n");
	logHex(encData.value().iv.data(), 12);
	printf("tag\n");
	logHex(encData.value().tag.data(), 16);

	// 복호화 테스트
	TeeAes teeAesDecrypt;
	if (teeAesDecrypt.init() == false)
	{
		return 0;
	}

	if (teeAesDecrypt.loadOrGenKey("alias0001") == false)
	{
		return 0;
	}	
	auto decData = teeAesDecrypt.decrypt(encData.value().cipher, encData.value().iv, aad, encData.value().tag);
	if (decData.has_value() == false)
	{
		printf("decrypt failed\n");
		return 0;
	}

	printf("plain\n");
	logHex(decData.value().data(), encData.value().cipher.size());

	return 0;
}
