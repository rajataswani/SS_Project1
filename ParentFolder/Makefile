CC = gcc
CFLAGS = -Wall -Wextra -pthread -O2

all: server client

server: server.o storage.o anomaly.o sha256.o
	$(CC) $(CFLAGS) -o server server.o storage.o anomaly.o sha256.o

client: client.o
	$(CC) $(CFLAGS) -o client client.o

server.o: server.c models.h protocol.h storage.h anomaly.h sha256.h
	$(CC) $(CFLAGS) -c server.c

client.o: client.c models.h protocol.h
	$(CC) $(CFLAGS) -c client.c

storage.o: storage.c storage.h models.h sha256.h
	$(CC) $(CFLAGS) -c storage.c

anomaly.o: anomaly.c anomaly.h models.h storage.h
	$(CC) $(CFLAGS) -c anomaly.c

sha256.o: sha256.c sha256.h
	$(CC) $(CFLAGS) -c sha256.c

clean:
	rm -f server client *.o
	rm -rf data/*.tmp* data/sessions/*.lock
