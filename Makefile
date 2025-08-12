.PHONY: all clean

all:
	mkdir -p build
	gcc src/main.c -o build/init -static

clean:
	rm -fr build
