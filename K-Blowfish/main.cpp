#include <iostream>
#include <fstream>
#include <algorithm>
#include <string>
#include <vector>
#include "BFCodec.h"

bool isHexString(const std::string& s)
{
	return std::all_of(s.begin(), s.end(), [](char c) { return std::isxdigit(c); });
}

std::vector<uint8_t> hexStringToBytes(const std::string& hex)
{
	std::vector<uint8_t> bytes;
	for (size_t i = 0; i < hex.length(); i += 2)
	{
		uint8_t byte = std::stoi(hex.substr(i, 2), nullptr, 16);
		bytes.push_back(byte);
	}
	return bytes;
}

int main(int argc, char* argv[])
{
	std::string ivHex, keyHex, inputFilePath, outputFilePath;
	bool isEncryptionMode = false;

	for (int i = 1; i < argc; i++)
	{
		std::string arg(argv[i]);
		if (arg == "--iv")
		{
			ivHex = argv[++i];
		}
		else if (arg == "--key")
		{
			keyHex = argv[++i];
		}
		//else if (arg == "-e" || arg == "--encrypt" || arg == "--encryption" || arg == "--encipher" || arg == "--enc")
		//{
		//	isEncryptionMode = true;
		//}
	}

	if (argc >= 6)
	{
		inputFilePath = argv[argc - 2];
		outputFilePath = argv[argc - 1];
	}

	if (inputFilePath.empty() || outputFilePath.empty() || ivHex.empty() || keyHex.empty() || !isHexString(ivHex) || !isHexString(keyHex))
	{
		std::cerr << "Invalid arguments.\nUsage: " << argv[0] << " --iv <IV Hex> --key <Key Hex> INPUT_FILE OUTPUT_FILE" << std::endl;
		return 1;
	}

	std::cout << "Open input file: " << inputFilePath << std::endl;
	std::ifstream inputFile(inputFilePath, std::ios::binary);

	if (!inputFile)
	{
		std::cerr << "Could not open input file: " << inputFilePath << std::endl;
		return 1;
	}

	std::vector<uint8_t> buffer{ std::istreambuf_iterator<char>(inputFile), std::istreambuf_iterator<char>() };
	inputFile.close();

	if (buffer.empty())
	{
		std::cerr << "Error: unable to read input file." << std::endl;
		return 1;
	}

	auto bfCodec = new BFCodec(hexStringToBytes(ivHex), hexStringToBytes(keyHex));

	if (isEncryptionMode)
	{
		if (!bfCodec->encipher(buffer))
		{
			std::cerr << "Encryption failed." << std::endl;
			return 1;
		}
		std::cout << "Successfully encrypted." << std::endl;
	}
	else
	{
		if (!bfCodec->decipher(buffer))
		{
			std::cerr << "Decryption failed." << std::endl;
			return 1;
		}
		std::cout << "Successfully decrypted." << std::endl;
	}

	std::ofstream outputFile(outputFilePath, std::ios::binary);

	if (!outputFile)
	{
		std::cerr << "Could not open output file: " << outputFilePath << std::endl;
		return 1;
	}

	outputFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
	outputFile.close();

	std::cout << "Processed data successfully written to: " << outputFilePath << std::endl;

	return 0;
}
