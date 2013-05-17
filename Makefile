CC = g++
CPPFLAGS = -Wall -g
LDFLAGS = -g

BOTAN_CPPFLAGS = $(CPPFLAGS) -I/usr/include/botan-1.10
BOTAN_LDFLAGS = $(LDFLAGS) -lbotan-1.10

build: aes-botan aes-gcrypt

botan: aes-botan
	./aes-botan -f input -p "secret" | ./aes-botan -f input.enc -p "secret" --decrypt ; diff input input.enc.dec

aes-botan: aes-botan.o main.o
	$(CC) -o $@ $^ $(BOTAN_LDFLAGS)

aes-botan.o: aes-botan.cpp
	$(CC) -c $(BOTAN_CPPFLAGS) -o $@ $^

aes-gcrypt: aes-gcrypt.o main.o
	$(CC) -o$@ $^ $(LDFLAGS) `libgcrypt-config --libs`

aes-gcrypt.o: aes-gcrypt.cpp
	$(CC) -o $@ -c $^ `libgcrypt-config --cflags`

main.o: main.cpp

clean:
	rm *.o aes-botan aes-dcrypt
