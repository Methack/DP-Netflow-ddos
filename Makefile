NAME=main
PROGRAM=ndd
OBJFILES=$(NAME).o comm.o config.o db.o ndd.o
CC=gcc
CFLAGS=-Wall -Wextra -Werror -DNDEBUG
LDFLAGS=-lnf -lpq -pthread
%.o : %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $<
all: $(NAME)
$(NAME): $(OBJFILES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJFILES) -o $(PROGRAM)
clean:
	rm -f *.o $(PROGRAM)


