#include <botan/botan.h>
#include <botan/pbkdf.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>

using namespace Botan;

#define OPTSTR "f:p:D"
#define KEY_SZ	32
#define IV_SZ	16
#define PBKDF_STR	"PBKDF2(SHA-256)"
#define PBKDF_ITER	10000
#define CIPHER_TYPE	"AES-256"
#define CIPHER_MODE	"/CBC"
#define PASS_PREFIX	"BLK"
#define IVL_PREFIX	"IVL"
#define ENC_FILE_EXT	".enc"
#define DEC_FILE_EXT	".dec"

const struct option longopts[] =
{
	{"file", required_argument, NULL, 'f'},
	{"pass", required_argument, NULL, 'p'},
	{"decrypt", no_argument, NULL, 'D'},
};

void print_usage(char *program_name)
{
	printf("Usage: %s\n"\
		"\t-f,,--file=INPUT_FILE\tInput file with cleartext\n"\
		"\t-p,--pass=PASSPHRASE\tPassphrase\n"\
		"\t-D,--decrypt\tFor decryption, encrypion is default", program_name);
}

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
		SecureVector<byte> salt = rng.random_vec(KEY_SZ/2);
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
	std::cout << "decrypt";
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


int main(int argc, char **argv)
{
	int opt, longindex;
	std::stringstream ss;
	std::string filename = "", passphrase = "";
	bool decrypt = false;

	while ((opt = getopt_long(argc, argv, OPTSTR, longopts, &longindex)) != -1)
	{
		switch (opt)
		{
			case 'f':
				filename = std::string(optarg);
				break;
			case 'p':
				passphrase = std::string(optarg);
				break;
			case 'D':
				decrypt = true;
				break;
			default:
				print_usage(argv[0]);
		}
	}

	if(filename.empty())
	{
		std::cerr <<  "Please add -f,--file=INPUT_FILE\n";
		exit(1);
	}
	if (passphrase.empty())
	{
		std::cerr << "Please add -p,--pass=PASSPHRASE\n";
		exit(1);
	}

	std::ifstream in(filename.c_str(), std::ios::binary);
	if (!in)
	{
		std::cerr << "Couldn't open input file\n";
		exit(1);
	}
	std::string extension = decrypt? DEC_FILE_EXT : ENC_FILE_EXT;
	std::ofstream out((filename + extension).c_str());
	if (!out)
	{
		std::cerr << "Couldn't open output file\n";
		exit(1);
	}
	
	if(!decrypt)
		aes_encrypt(in, out, passphrase);
	else
		aes_decrypt(in, out, passphrase);
	return 0;
}
