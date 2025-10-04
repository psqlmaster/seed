gcc -o seed seed.c -lssl -lcrypto

./seed -c 2 -w 24 -b bip44
./seed -c 200 -w 12 -b bip49
