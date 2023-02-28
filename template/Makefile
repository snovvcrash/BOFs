BOFNAME := backdoor-scmanager.x64
BOFDIR  := dist
CC_x64  := x86_64-w64-mingw32-gcc

all:
	@cp ../beacon.h .
	@mkdir -p $(BOFDIR)
	$(CC_x64) -o $(BOFDIR)/$(BOFNAME).o -c entry.c

clean:
	rm -f beacon.h $(BOFDIR)/$(BOFNAME).o
