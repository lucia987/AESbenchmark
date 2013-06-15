CC = g++
CPPFLAGS = -Wall -g
LDFLAGS = -g

BOTAN_CPPFLAGS = $(CPPFLAGS) -I/usr/include/botan-1.10
BOTAN_LDFLAGS = $(LDFLAGS) -lbotan-1.10
GCRYPT_LDFLAGS = $(LDFLAGS) -lgcrypt -lgpg-error
CRYPTOPP_CPPFLAGS = -I/usr/include/cryptopp
CRYPTOPP_LDFLAGS = -lcryptopp -lpthread

build: aes-botan aes-gcrypt aes-cryptopp

botan: aes-botan
	./aes-botan -f input -p "secret" > salt.txt; cat salt.txt | ./aes-botan -f input.enc -p "secret" --decrypt ; diff input input.enc.dec

gcrypt: aes-gcrypt
	./aes-gcrypt -f input -p "secret" > salt.txt; cat salt.txt | ./aes-gcrypt -f input.enc -p "secret" --decrypt ; diff input input.enc.dec

cryptopp: aes-cryptopp
	./aes-cryptopp -f input -p "secret" > salt.txt; cat salt.txt | ./aes-cryptopp -f input.enc -p "secret" -D ; diff input input.enc.dec

aes-botan: aes-botan.o main.o
	$(CC) -o $@ $^ $(BOTAN_LDFLAGS)

aes-botan.o: aes-botan.cpp
	$(CC) -c $(BOTAN_CPPFLAGS) -o $@ $^

aes-gcrypt: aes-gcrypt.o main.o base64.o
	$(CC) -o $@ $^ $(GCRYPT_LDFLAGS)

aes-gcrypt.o: aes-gcrypt.cpp
	$(CC) -o $@ -c $^

aes-cryptopp: aes-cryptopp.o main.o base64.o
	$(CC) -o $@ $^ $(CRYPTOPP_LDFLAGS)

aes-cryptopp.o: aes-cryptopp.cpp
	$(CC) -c $(CRYPTOPP_CPPFLAGS) -o $@ $^

main.o: main.cpp

base64.o: base64.cpp

clean:
	rm *.o aes-botan aes-gcrypt
