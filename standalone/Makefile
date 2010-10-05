all: sha256crypt sha512crypt md5crypt descrypt

clean:
	rm -rf sha256crypt
	rm -rf sha512crypt
	rm -rf md5crypt
	rm -rf md5crypt.o
	rm -rf md5.o
	rm -rf des.o
	rm -rf descrypt
	rm -rf descrypt.o

sha256crypt: sha256crypt.c
	gcc -Wall -fPIC -DPIC -o sha256crypt sha256crypt.c

sha512crypt: sha512crypt.c
	gcc -Wall -fPIC -DPIC -o sha512crypt sha512crypt.c

md5crypt: md5crypt.o md5.o
	gcc -Wall -fPIC -DPIC -o md5crypt md5crypt.o md5.o

md5crypt.o: md5crypt.c md5.h
	gcc -Wall -fPIC -DPIC -o md5crypt.o -c md5crypt.c

md5.o: md5.c md5.h
	gcc -Wall -fPIC -DPIC -o md5.o -c md5.c

descrypt: descrypt.o des.o
	gcc -Wall -fPIC -DPIC -o descrypt descrypt.o des.o

descrypt.o: descrypt.c des.h
	gcc -Wall -fPIC -DPIC -o descrypt.o -c descrypt.c

des.o: des.c des.h
	gcc -Wall -fPIC -DPIC -o des.o -c des.c