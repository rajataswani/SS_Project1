#!/bin/bash
set -e

echo "Compiling Banking Management System..."
gcc -Wall -Wextra -pthread -O2 -c sha256.c
gcc -Wall -Wextra -pthread -O2 -c storage.c
gcc -Wall -Wextra -pthread -O2 -c anomaly.c
gcc -Wall -Wextra -pthread -O2 -c server.c
gcc -Wall -Wextra -pthread -O2 -c client.c

gcc -Wall -Wextra -pthread -O2 -o server server.o storage.o anomaly.o sha256.o
gcc -Wall -Wextra -pthread -O2 -o client client.o

echo "Build successful! Executables 'server' and 'client' created."
