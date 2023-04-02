#include <iostream>
#include <vector>
#include "BFCodec.h"

BFCodec::BFCodec(const uint8_t* iv, size_t ivSize, const uint8_t* key, size_t keySize)
{
	if (ivSize != 8)
	{
		throw std::runtime_error("Invalid IV size");
	}
	std::copy(iv, iv + 8, this->iv);
	setKey(key, keySize);
}

BFCodec::BFCodec(const std::vector<uint8_t> iv, const std::vector<uint8_t> key)
{
	if (iv.size() != 8)
	{
		throw std::runtime_error("Invalid IV size");
	}
	std::copy(iv.begin(), iv.end(), this->iv);
	setKey(key.data(), key.size());
}

bool BFCodec::decipher(std::vector<uint8_t>& data)
{
	size_t inputDataSize = data.size();
	size_t inputPayloadSize = inputDataSize - 8;

	if (inputDataSize < 8)
	{
		return false;
	}

		uint32_t decryptedPayloadSize = (data[inputPayloadSize + 0] << 24) | (data[inputPayloadSize + 1] << 16) | (data[inputPayloadSize + 2] << 8) | data[inputPayloadSize + 3];
		uint32_t encryptedPayloadSize = (data[inputPayloadSize + 4] << 24) | (data[inputPayloadSize + 5] << 16) | (data[inputPayloadSize + 6] << 8) | data[inputPayloadSize + 7];

	if (inputPayloadSize != encryptedPayloadSize || inputPayloadSize != ((decryptedPayloadSize + 7) / 8) * 8)
		{
		return false;
	}

			uint32_t ivLeft = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
			uint32_t ivRight = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];

			for (size_t i = 0; i < inputPayloadSize; i += 8)
			{
				uint32_t leftData = (data[i + 0] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];
				uint32_t rightData = (data[i + 4] << 24) | (data[i + 5] << 16) | (data[i + 6] << 8) | data[i + 7];

				uint32_t left = leftData;
				uint32_t right = rightData;

				blockDecipher(&left, &right);

				left ^= ivLeft;
				right ^= ivRight;

		for (int j = 0; j < 4; ++j)
		{
			uint8_t shift = 24 - 8 * j;
			data[i + j] = static_cast<uint8_t>((left >> shift) & 0xFF);
			data[i + j + 4] = static_cast<uint8_t>((right >> shift) & 0xFF);
		}

				ivLeft = leftData;
				ivRight = rightData;
			}

			data.resize(decryptedPayloadSize);

			return true;
		}

bool BFCodec::encipher(std::vector<uint8_t>& data)
{
	size_t inputDataSize = data.size();

	if (inputDataSize <= 0)
	{
	return false;
}

	size_t encryptedPayloadSize = ((inputDataSize + 7) / 8) * 8;
	data.resize(encryptedPayloadSize + 8);

	uint32_t ivLeft = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
	uint32_t ivRight = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];

	for (size_t i = 0; i < encryptedPayloadSize; i += 8)
{
		uint32_t leftData = 0;
		uint32_t rightData = 0;

		for (int j = 0; j < 4; j++)
		{
			uint8_t shift = 24 - 8 * j;
			if (i + j < inputDataSize)
			{
				leftData |= (data[i + j] << shift);
			}
			if (i + j + 4 < inputDataSize)
			{
				rightData |= (data[i + j + 4] << shift);
			}
		}

		leftData ^= ivLeft;
		rightData ^= ivRight;

		blockEncipher(&leftData, &rightData);

		for (int j = 0; j < 4; j++)
		{
			uint8_t shift = 24 - 8 * j;
			if (i + j < inputDataSize)
			{
				data[i + j] = static_cast<uint8_t>((leftData >> shift) & 0xff);
			}
			if (i + j + 4 < inputDataSize)
			{
				data[i + j + 4] = static_cast<uint8_t>((rightData >> shift) & 0xff);
			}
		}

		ivLeft = leftData;
		ivRight = rightData;
	}

	for (int i = 0; i < 4; i++)
	{
		uint8_t shift = 24 - 8 * i;
		data[encryptedPayloadSize + i] = static_cast<uint8_t>((inputDataSize >> shift) & 0xff);
		data[encryptedPayloadSize + i + 4] = static_cast<uint8_t>((encryptedPayloadSize >> shift) & 0xff);
	}

	return true;
}

void BFCodec::blockDecipher(uint32_t* left, uint32_t* right)
{
	uint32_t tempLeft = *left;
	uint32_t tempRight = *right;

	for (int i = 17; i > 1; i--)
	{
		uint32_t temp = tempLeft ^ p[i];
		tempLeft = (
			s[(temp >> 24) & 0xFF] +
			s[((temp >> 16) & 0xFF) + 0x100]
			) ^ tempRight ^ (
				s[((temp >> 8) & 0xFF) + 0x200] +
				s[((temp >> 0) & 0xFF) + 0x300]
				);
		tempRight = temp;
	}

	*left = tempRight ^ p[0];
	*right = tempLeft ^ p[1];
}

void BFCodec::blockEncipher(uint32_t* left, uint32_t* right)
{
	uint32_t tempLeft = *left;
	uint32_t tempRight = *right;

	for (int i = 0; i < 16; i++)
	{
		uint32_t temp = tempLeft ^ p[i];
		tempLeft = (
			s[(temp >> 24) & 0xFF] +
			s[((temp >> 16) & 0xFF) + 0x100]
			) ^ tempRight ^ (
				s[((temp >> 8) & 0xFF) + 0x200] +
				s[((temp >> 0) & 0xFF) + 0x300]
				);
		tempRight = temp;
	}

	*left = tempRight ^ p[17];
	*right = tempLeft ^ p[16];
}

void BFCodec::setKey(const uint8_t* key, size_t keySize)
{
	// Initialize S-boxes
	std::copy(std::begin(initialSBoxes), std::end(initialSBoxes), std::begin(s));

	// XOR the key with the P-array
	for (int i = 0, j = 0; i < 18; i++)
	{
		p[i] = (
			static_cast<uint32_t>(key[(j + 0) % keySize] << 24) |
			static_cast<uint32_t>(key[(j + 1) % keySize] << 16) |
			static_cast<uint32_t>(key[(j + 2) % keySize] << 8) |
			key[(j + 3) % keySize]
			) ^ initialPArray[i];
		j = (j + 4) % keySize;
	}

	uint32_t left = 0;
	uint32_t right = 0;

	for (int i = 0; i < 18; i += 2)
	{
		uint32_t temp = 0;
		for (int j = 0; j < 16; j++)
		{
			temp = p[j] ^ left;
			left = (
				s[(temp >> 24) & 0xFF] +
				s[((temp >> 16) & 0xFF) + 0x100]
				) ^ right ^ (
					s[((temp >> 8) & 0xFF) + 0x200] +
					s[((temp >> 0) & 0xFF) + 0x300]
					);
			right = temp;
		}
		right = p[16] ^ left;
		left = p[17] ^ temp;
		p[i] = left;
		p[i + 1] = right;
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 256; j += 2)
		{
			uint32_t temp = 0;
			for (int k = 0; k < 16; k++)
			{
				temp = p[k] ^ left;
				left = (
					s[(temp >> 24) & 0xFF] +
					s[((temp >> 16) & 0xFF) + 0x100]
					) ^ right ^ (
						s[((temp >> 8) & 0xFF) + 0x200] +
						s[((temp >> 0) & 0xFF) + 0x300]
						);
				right = temp;
			}
			right = p[16] ^ left;
			left = p[17] ^ temp;
			s[256 * i + j] = left;
			s[256 * i + j + 1] = right;
		}
	}
}
