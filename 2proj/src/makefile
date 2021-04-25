CC=g++
CFLAGS=-g -Wall 
PROG=ipk-sniffer
SOURCE=main.o argparse.o myHandler.o
LOGIN=xpupak01

all: $(PROG)

$(PROG): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(PROG) -lpcap
	
%.o: %.c
	$(CC) $(CFLAGS) -c $<

run: $(PROG)
	sudo ./$(PROG) -i wlp4s0

clean:
	rm *.o
	rm $(PROG)
	rm $(LOGIN).zip

zip:
	zip $(LOGIN).zip *.cpp *.h makefile