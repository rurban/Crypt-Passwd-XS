all: sha256crypt sha512crypt md5crypt

clean:
	rm -rf sha256crypt
	rm -rf sha512crypt
	rm -rf md5crypt

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