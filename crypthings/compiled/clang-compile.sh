#!/usr/bin/env bash
#
clang ../rc4-crypt.c ../../ciphers/rc4/rc4.c ../../utils/utils.c -o rc4-crypt.o -Wall -Wextra
clang ../aes-ofb-crypt.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-ofb-crypt.o -Wall -Wextra
clang ../des56-ofb-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o des56-ofb-crypt.o -Wall -Wextra
clang ../des56-ca-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o des56-ca-crypt.o -Wall -Wextra
clang ../tdea-tofb-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-tofb-crypt.o -Wall -Wextra
clang ../scrambler-crypt.c ../../ciphers/scrambler/scrambler.c ../../utils/utils.c -o scrambler-crypt.o -Wall -Wextra
clang ../aes-key-unwrap.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-key-unwrap.o -Wall -Wextra
clang ../aes-key-wrap.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-key-wrap.o -Wall -Wextra
clang ../tdea-key-wrap.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-key-wrap.o -Wall -Wextra
clang ../tdea-key-unwrap.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-key-unwrap.o -Wall -Wextra
clang ../straight-crypt.c ../../utils/utils.c -o straight-crypt.o -Wall -Wextra
clang ../lfsr-recovery-tool.c ../../utils/utils.c -o lfsr-recovery-tool.o -Wall -Wextra
clang ../lfsr-expansion-tool.c ../../utils/utils.c -o lfsr-expansion-tool.o -Wall -Wextra