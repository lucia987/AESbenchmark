#include <gcrypt.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include "util.h"

#define OPTSTR "f:p:D"
#define ENC_FILE_EXT	".enc"
#define DEC_FILE_EXT	".dec"

void aes_encrypt(std::ifstream& in, std::ofstream& out, std::string passphrase);
void aes_decrypt(std::ifstream& in, std::ofstream& out, std::string passphrase);

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

int main(int argc, char **argv)
{
	int opt, longindex;
	std::string filename = "", passphrase = "";
	bool decrypt = false;

	while ((opt = getopt_long(argc, argv, OPTSTR, longopts, &longindex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
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

	DIE(filename.empty(), "Please add -f,--file=INPUT_FILE");
	DIE(passphrase.empty(), "Please add -p,--pass=PASSPHRASE");

	std::ifstream in(filename.c_str(), std::ios::binary);
	DIE(!in, "Couldn't open input file");

	std::string extension = decrypt? DEC_FILE_EXT : ENC_FILE_EXT;
	std::ofstream out((filename + extension).c_str());
	DIE(!out, "Couldn't open output file");
	
	if(!decrypt)
		aes_encrypt(in, out, passphrase);
	else
		aes_decrypt(in, out, passphrase);
	
	return 0;
}
