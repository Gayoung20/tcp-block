LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o ethhdr.o iphdr.o tcphdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f tcp-block *.o