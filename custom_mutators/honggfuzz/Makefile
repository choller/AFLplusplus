
CFLAGS = -O3 -funroll-loops -fPIC -Wl,-Bsymbolic

all: honggfuzz-mutator.so honggfuzz-2b-chunked-mutator.so

honggfuzz-mutator.so:	honggfuzz.c input.h mangle.c ../../src/afl-performance.c
	$(CC) $(CFLAGS) -I../../include -I. -shared -o honggfuzz-mutator.so honggfuzz.c mangle.c ../../src/afl-performance.c

honggfuzz-2b-chunked-mutator.so:	honggfuzz.c input.h mangle.c ../../src/afl-performance.c
	$(CC) $(CFLAGS) -DHONGGFUZZ_2B_CHUNKED -I../../include -I. -shared -o honggfuzz-2b-chunked-mutator.so honggfuzz.c mangle.c ../../src/afl-performance.c

update:
	@# seriously? --unlink is a dud option? sigh ...
	rm -f mangle.c mangle.h honggfuzz.h
	wget --unlink https://github.com/google/honggfuzz/raw/master/mangle.c
	wget --unlink https://github.com/google/honggfuzz/raw/master/mangle.h
	wget --unlink https://github.com/google/honggfuzz/raw/master/honggfuzz.h

clean:
	rm -f *.o *~ *.so core
