#include <gcrypt.h>
#include <gpg-error.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "util.h"
#include "base64.h"

char* init_gcrypt_key_iv(
	gcry_cipher_hd_t& handle,
	std::string passphrase,
	std::string user_salt)
{
	unsigned char	salt[SALT_SZ],
			key[KEY_SZ],
			iv[IV_SZ];
	gcry_error_t ret;

	/* gcrypt initialization */
	gcry_check_version (NULL);

	if (user_salt.empty())
	{
		/* Generate salt randomly */
		gcry_randomize(salt, sizeof(salt), GCRY_WEAK_RANDOM);
		std::cout << base64_encode(salt, SALT_SZ);
	}
	else
	{
		/* Copy salt from user */
		std::string tmp_salt = base64_decode(user_salt);
		memcpy(salt, tmp_salt.c_str(), SALT_SZ);
	}

	/* Generate key from passhrase */
	std::string keypass = KEY_PREFIX + passphrase;
	ret = gcry_kdf_derive(keypass.c_str(), keypass.size(),
		GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, SALT_SZ,
		PBKDF_ITER, KEY_SZ, key);
	DIE(ret, "gcry_kdf_derive on key");

	/* Generate initialization vector from passphrase */
	std::string ivpass = IV_PREFIX + passphrase;
	ret = gcry_kdf_derive(ivpass.c_str(), ivpass.size(),
		GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, SALT_SZ,
		PBKDF_ITER, IV_SZ, iv);
	DIE(ret, "gcry_kdf_derive on iv");

	memcpy(key, passphrase.c_str(), KEY_SZ);
	memset(iv, 0, IV_SZ);

	ret = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	DIE(ret, "gcry_cipher_open");
	
	ret = gcry_cipher_setkey(handle, key, KEY_SZ);
	DIE(ret, "gcry_cipher_setkey");

	ret = gcry_cipher_setiv(handle, iv, IV_SZ);
	DIE(ret, "gcry_cipher_setiv");
}

void aes_encrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	int size;
	gcry_cipher_hd_t handle;
	gcry_error_t ret;

	/* Determine input file size */
	in.seekg(0, std::ios::end);
	size = in.tellg();
	size = (size % BLOCK_SZ)? (size + (BLOCK_SZ - size % BLOCK_SZ)) : size;
	
	/* Define plain and cipher strings according to input file size */
	char *plain = new char[size];
	char *cipher = new char[size];

	/* Read input */
	in.seekg(0, std::ios::beg);
	std::streambuf* raw_buffer = in.rdbuf();
	raw_buffer->sgetn(plain, size);

	init_gcrypt_key_iv(handle, passphrase, std::string(""));

	ret = gcry_cipher_encrypt(handle, (unsigned char *)&cipher[0], size,
		(unsigned char *)&plain[0], size);
	DIE(ret, "gcry_cipher_encrypt");

	gcry_cipher_close(handle);
	out << cipher;

	delete [] plain;
	delete [] cipher;
}

void aes_decrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	int size;
	gcry_cipher_hd_t handle;
	gcry_error_t ret;
	std::string saltstr;

	/* Determine input file size */
	in.seekg(0, std::ios::end);
	size = in.tellg();
	
	/* Define plain and cipher strings according to input file size */
	char *plain = new char[size];
	char *cipher = new char[size];

	/* Read input */
	in.seekg(0, std::ios::beg);
	std::streambuf* raw_buffer = in.rdbuf();
	raw_buffer->sgetn(cipher, size);

	std::cin >> saltstr;
	init_gcrypt_key_iv(handle, passphrase, saltstr);

	ret = gcry_cipher_decrypt(handle, (unsigned char *)&plain[0], size,
		(unsigned char *)&cipher[0], size);
	DIE(ret, "gcry_cipher_decrypt");

	gcry_cipher_close(handle);
	out << plain;

	delete [] plain;
	delete [] cipher;
}
