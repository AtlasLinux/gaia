.PHONY: all clean

all:
	mkdir -p build
	gcc src/main.c -o build/gaia -static

clean:
	rm -fr build
