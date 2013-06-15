#include <botan/botan.h>
#include <botan/pbkdf.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "util.h"

using namespace Botan;

#define PBKDF_STR	"PBKDF2(SHA-1)"
#define CIPHER_TYPE	"AES-256"
#define CIPHER_MODE	"/CBC"

std::string b64_encode(const SecureVector<byte>& in)
{
	Pipe pipe(new Base64_Encoder);
	pipe.process_msg(in);
	return pipe.read_all_as_string();
}

SecureVector<byte> b64_decode(const std::string& in)
{
	Pipe pipe(new Base64_Decoder);
	pipe.process_msg(in);
	return pipe.read_all();
}

void init_botan_key_iv(
	std::string passphrase,
	std::string user_salt,
	OctetString &key,
	InitializationVector &iv)
{
	AutoSeeded_RNG rng;
	SecureVector<byte> salt;

	/* Generate salt randomly */
	if (user_salt.size() == 0)
	{
		salt = rng.random_vec(SALT_SZ);
		std::cout << b64_encode(salt);
	}
	else
	{
		salt = b64_decode(user_salt);
	}

	PBKDF* pbkdf = get_pbkdf(PBKDF_STR);

	/* Generate AES key from passphrase */
	key = pbkdf->derive_key(KEY_SZ, KEY_PREFIX + passphrase,
		&salt[0], salt.size(), PBKDF_ITER);

	/* Generate IV from passphrase */
	iv = pbkdf->derive_key(IV_SZ, IV_PREFIX + passphrase,
		&salt[0], salt.size(), PBKDF_ITER);

}

void aes_encrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	try
	{
		LibraryInitializer init;
		OctetString aes_key;
		InitializationVector iv;

		init_botan_key_iv(passphrase, std::string(""), aes_key, iv);

		/* Add AES/CBC filter to a Botan::Pipe */
		Pipe pipe(get_cipher(std::string(CIPHER_TYPE) + CIPHER_MODE, aes_key, iv, ENCRYPTION));
		
		/* Write B64 encrypted salt to stdout */
		pipe.start_msg();
		in >> pipe;
		pipe.end_msg();

		out << pipe.read_all_as_string(0);
	}
	catch(std::exception& e)
	{
		std::cerr << "Exception:" << e.what() << "\n";
	}
}

void aes_decrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	try
	{
		LibraryInitializer init;
		OctetString aes_key;
		InitializationVector iv;

		/* Read salt from input */
		std::string salt_str;
		std::cin >> salt_str;

		init_botan_key_iv(passphrase, salt_str, aes_key, iv);

		/* Add AES/CBC filter to a Botan::Pipe */
		Pipe pipe(get_cipher(std::string(CIPHER_TYPE) + CIPHER_MODE, aes_key, iv, DECRYPTION));
		
		/* Write B64 encrypted salt to stdout */
		pipe.start_msg();
		in >> pipe;
		pipe.end_msg();

		out << pipe.read_all_as_string(0);
	}
	catch(std::exception& e)
	{
		std::cerr << "Exception:" << e.what() << "\n";
	}
}
