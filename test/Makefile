BOFNAME := test_invoke_bof
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -Wall -o ./$(BOFNAME).x64.o -c main.c -masm=intel

clean:
	rm -f ./$(BOFNAME).x64.o
