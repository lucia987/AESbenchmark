#include <iostream>
#include <fstream>
#include <sstream>
#include "util.h"
#include "base64.h"

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CBC_Mode;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/pwdbased.h>

void init_cryptopp_key_iv(
	std::string passphrase,
	std::string user_salt,
	SecByteBlock &key,
	SecByteBlock &iv)
{
	AutoSeededRandomPool prng;
	SecByteBlock salt;

	if(user_salt.size() == 0)
	{
		salt = SecByteBlock(SALT_SZ);
		prng.GenerateBlock(salt, salt.size());
		std::cout << base64_encode((unsigned char *)salt.begin(), SALT_SZ);
	}
	else
	{
		salt = SecByteBlock((unsigned char *)(base64_decode(user_salt).c_str()), SALT_SZ);
	}
	
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf;
	std::string iv_pass = IV_PREFIX + passphrase;
	std::string key_pass = KEY_PREFIX + passphrase;

	pbkdf.DeriveKey(
		iv, iv.size(),
		0x00,
		(byte *) iv_pass.c_str(), iv_pass.size(),
		salt, salt.size(),
		PBKDF_ITER);
	pbkdf.DeriveKey(
		key, key.size(),
		0x00,
		(byte *) key_pass.c_str(), key_pass.size(),
		salt, salt.size(),
		PBKDF_ITER);
}

void aes_encrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	SecByteBlock iv(IV_SZ);
	SecByteBlock key(KEY_SZ);
	int size;

	/* Determine input file size */
	in.seekg(0, std::ios::end);
	size = in.tellg();
	//size = (size % BLOCK_SZ)? (size + (BLOCK_SZ - size % BLOCK_SZ)) : size;
	
	/* Define plain and cipher strings according to input file size */
	char *plain = new char[size];
	std::string cipher;

	/* Read input */
	in.seekg(0, std::ios::beg);
	std::streambuf* raw_buffer = in.rdbuf();
	raw_buffer->sgetn(plain, size);

	init_cryptopp_key_iv(passphrase, std::string(""), key, iv);

	try {
		CBC_Mode<AES>::Encryption encrypt(key, key.size(), iv);

		// The StreamTransformationFilter removes padding as
		// required
		StringSource encryptor(plain, true,
			new StreamTransformationFilter(encrypt,
				new StringSink(cipher)
			)
		);
		out << cipher;
	}
	catch(const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}

void aes_decrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	SecByteBlock key(KEY_SZ);
	SecByteBlock iv(IV_SZ);
	int size;

	/* Determine input file size */
	in.seekg(0, std::ios::end);
	size = in.tellg();
	//size = (size % BLOCK_SZ)? (size + (BLOCK_SZ - size % BLOCK_SZ)) : size;
	
	/* Define plain and cipher strings according to input file size */
	char *cipher = new char[size];
	std::string plain;

	/* Read input */
	in.seekg(0, std::ios::beg);
	std::streambuf* raw_buffer = in.rdbuf();
	raw_buffer->sgetn(cipher, size);

	/* Read salt from input */
	std::string salt_str;
	std::cin >> salt_str;
	init_cryptopp_key_iv(passphrase, salt_str, key, iv);

	try {
		CBC_Mode<AES>::Decryption decrypt(key, key.size(), iv);

		// The StreamTransformationFilter removes padding as
		// required
		StringSource s(cipher, true,
			new StreamTransformationFilter(decrypt,
				new StringSink(plain)
			)
		);
		out << plain;
	}
	catch(const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}
