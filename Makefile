full:
	make clean
	make build

build:
	mkdir -p bin
	gcc -O3 -o bin/masl main.c -lssl -lcrypto

clean:
	rm -rf bin