#include <botan/botan.h>
#include <botan/pbkdf.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>

using namespace Botan;

#define KEY_SZ	32
#define IV_SZ	16
#define SALT_SZ	16
#define PBKDF_STR	"PBKDF2(SHA-256)"
#define PBKDF_ITER	10000
#define CIPHER_TYPE	"AES-256"
#define CIPHER_MODE	"/CBC"
#define PASS_PREFIX	"BLK"
#define IVL_PREFIX	"IVL"

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

void aes_encrypt(std::ifstream& in, std::ofstream& out, std::string passphrase)
{
	try
	{
		LibraryInitializer init;

		PBKDF* pbkdf = get_pbkdf(PBKDF_STR);
		AutoSeeded_RNG rng;

		/* Generate salt randomly */
		SecureVector<byte> salt = rng.random_vec(SALT_SZ);
		std::cout << b64_encode(salt);
		
		/* Generate AES key from passphrase */
		OctetString aes_key = pbkdf->derive_key(KEY_SZ, PASS_PREFIX + passphrase,
			&salt[0], salt.size(), PBKDF_ITER);

		/* Generate IV from passphrase */
		InitializationVector iv = pbkdf->derive_key(IV_SZ, IVL_PREFIX + passphrase,
			&salt[0], salt.size(), PBKDF_ITER);

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

		PBKDF* pbkdf = get_pbkdf(PBKDF_STR);
		AutoSeeded_RNG rng;

		/* Read salt from input */
		std::string salt_str;
		std::cin >> salt_str;
		SecureVector<byte> salt = b64_decode(salt_str);
		
		/* Generate AES key from passphrase */
		OctetString aes_key = pbkdf->derive_key(KEY_SZ, PASS_PREFIX + passphrase,
			&salt[0], salt.size(), PBKDF_ITER);

		/* Generate IV from passphrase */
		InitializationVector iv = pbkdf->derive_key(IV_SZ, IVL_PREFIX + passphrase,
			&salt[0], salt.size(), PBKDF_ITER);

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
