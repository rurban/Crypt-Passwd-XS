all: sha256crypt sha512crypt md5crypt

clean:
	rm -rf sha256crypt
	rm -rf sha512crypt
	rm -rf md5crypt

sha256crypt: sha256crypt.c
	gcc -o sha256crypt sha256crypt.c

sha512crypt: sha512crypt.c
	gcc -o sha512crypt sha512crypt.c

md5crypt: md5crypt.c
	gcc -o md5crypt md5crypt.c
