CC:=gcc
AS:=as

INCDIR:=../include
BIN:=libopenasm_aarch64.so
TEST:=run_test

TESTSRC:=test.c
SRC:=../dwarf.c lib.c jit.c instf.c link.c
OBJ:=../dwarf.o lib.o jit.o instf.o link.o
INC:=$(INCDIR)/openasm.h $(INCDIR)/aarch64.h $(INCDIR)/dwarf.h

CFLAGS:=-g -ggdb -Wall -Wextra -pedantic -std=c11 -D_GNU_SOURCE=1 -fPIC -I..
LDFLAGS:=
ASFLAGS:=

.PHONY: all build clean mrproper

all: $(BIN)

build: $(BIN)

test: $(TEST)
	LD_LIBRARY_PATH=. ./$(TEST)

$(TEST): $(TESTSRC) $(BIN)
	$(CC) -o $@ $(CFLAGS) $(TESTSRC) $(LDFLAGS) -L. -lopenasm_aarch64

$(BIN): $(OBJ) $(INC)
	$(CC) -shared -o $(BIN) $(OBJ) $(LDFLAGS)

$(OBJ): %.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf $(OBJ)

mrproper: clean
	rm -rf $(BIN)
	rm -rf $(TEST)
