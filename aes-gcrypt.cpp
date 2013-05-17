#include <gcrypt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "util.h"

void init_gcrypt()
{
	gcry_check_version (NULL);
}

void aes_encrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	unsigned char	salt[SALT_SZ],
			key[KEY_SZ],
			iv[IV_SZ];
	int size;
	std::stringstream plainss;
	gcry_cipher_hd_t handle;
	gcry_error_t ret;

	/* Determine input file size */
	in.seekg(0, std::ios::end);
	size = in.tellg();
	
	/* Define plain and cipher strings according to input file size */
	char *plain = new char[size];
	char *cipher = new char[size];

	/* Read input */
	in.seekg(0, std::ios::beg);
	std::streambuf* raw_buffer = in.rdbuf();
	raw_buffer->sgetn(plain, size);

	/* Generate salt randomly */
	gcry_randomize(salt, sizeof(salt), GCRY_WEAK_RANDOM);

	/* Generate key from passhrase */
	std::string keypass = KEY_PREFIX + passphrase;
	ret = gcry_kdf_derive(keypass.c_str(), keypass.size(),
		GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, SALT_SZ,
		PBKDF_ITER, KEY_SZ, key);
	DIE(ret, "gcry_kdf_derive on key");

	/* generate initialization vector from passphrase */
	std::string ivpass = IV_PREFIX + passphrase;
	ret = gcry_kdf_derive(ivpass.c_str(), ivpass.size(),
		GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, SALT_SZ,
		PBKDF_ITER, IV_SZ, iv);
	DIE(ret, "gcry_kdf_derive on iv");

	ret = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	DIE(ret, "gcry_cipher_open");
	
	ret = gcry_cipher_setkey(handle, key, KEY_SZ);
	DIE(ret, "gcry_cipher_setkey");

	ret = gcry_cipher_setiv(handle, iv, IV_SZ);
	DIE(ret, "gcry_cipher_setiv");
	
	ret = gcry_cipher_encrypt(handle, (unsigned char *)&cipher[0], size,
		(unsigned char *)&plain[0], size);
	DIE(ret, "gcry_cipher_encrypt");

	gcry_cipher_close(handle);
}

void aes_decrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{

}
