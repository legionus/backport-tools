INCLUDE=-I../../

all: dictionary.o ciniparser.o

dictionary.o: dictionary.c dictionary.h
	$(CC) $(INCLUDE) -c -o $@ dictionary.c

ciniparser.o: ciniparser.c ciniparser.h
	$(CC) $(INCLUDE) -c -o $@ ciniparser.c

clean:
	@rm -f dictionary.o ciniparser.o
