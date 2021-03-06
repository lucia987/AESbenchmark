#ifndef UTIL_H
#define UTIL_H

#define KEY_SZ		32
#define BLOCK_SZ	16
#define IV_SZ		BLOCK_SZ
#define SALT_SZ		16
#define KEY_PREFIX	"BLK"
#define IV_PREFIX	"IVL"
#define PBKDF_ITER	8192

#define DIE(condition, message) { if (condition) { std::cerr << "ERROR " << message <<"\n"; exit(1); }}
#endif
