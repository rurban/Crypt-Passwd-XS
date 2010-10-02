all: sha256crypt sha512crypt

clean:
	rm -rf sha256crypt
	rm -rf sha512crypt

sha256crypt: sha256crypt.c
	gcc -o sha256crypt sha256crypt.c

sha512crypt: sha512crypt.c
	gcc -o sha512crypt sha512crypt.c
