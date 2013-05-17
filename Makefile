CC = g++
CPPFLAGS = -Wall -g -I/usr/include/botan-1.10 
LDFLAGS = -g -lbotan-1.10

botan_enc: aes-botan
	./aes-botan --file input --pass "secret"

botan_dec: aes-botan
	./aes-botan --file input.enc --pass "secret"

aes-botan: aes-botan.o
	$(CC) $^ -o $@ $(LDFLAGS)

aes-botan.o: aes-botan.cpp

clean:
	rm *.o aes-botan
