.PHONY: all clean

all:
	mkdir -p build
	clang src/main.c -o build/init -static

clean:
	rm -fr build
