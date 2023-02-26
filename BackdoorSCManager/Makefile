BOFNAME := backdoor-scmanager.x64
CC_x64 := x86_64-w64-mingw32-gcc
OBJDIR := dist

all:
	@cp ../beacon.h .
	@mkdir -p $(OBJDIR)
	$(CC_x64) -o $(OBJDIR)/$(BOFNAME).o -c entry.c

clean:
	rm -f beacon.h $(OBJDIR)/$(BOFNAME).o
