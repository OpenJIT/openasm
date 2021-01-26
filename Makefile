.PHONY: all clean mrproper aarch64/test aarch64/libopenasm_aarch64.so amd64/libopenasm_amd64.so amd64/test

all: aarch64/libopenasm_aarch64.so amd64/libopenasm_amd64.so

aarch64/libopenasm_aarch64.so:
	make -C aarch64

amd64/libopenasm_amd64.so:
	make -C amd64

aarch64/test:
	make -C aarch64 test

amd64/test:
	make -C amd64 test

clean:
	make -C aarch64 clean
	make -C amd64 clean

mrproper: clean
	make -C aarch64 mrproper
	make -C amd64 mrproper
