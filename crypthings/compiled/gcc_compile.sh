#! /bin/bash
#
gcc ../rc4-crypt.c ../../ciphers/rc4/rc4.c ../../utils/utils.c -o rc4-crypt.o -Wall -Wextra -Wpedantic
gcc ../aes-ofb-crypt.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-ofb-crypt.o -Wall -Wextra -Wpedantic
gcc ../des56-ofb-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o des56-ofb-crypt.o -Wall -Wextra -Wpedantic
gcc ../des56-ca-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o des56-ca-crypt.o -Wall -Wextra -Wpedantic
gcc ../tdea-tofb-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-tofb-crypt.o -Wall -Wextra -Wpedantic
gcc ../scrambler-crypt.c ../../ciphers/scrambler/scrambler.c ../../utils/utils.c -o scrambler-crypt.o -Wall -Wextra -Wpedantic
gcc ../aes-key-unwrap.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-key-unwrap.o -Wall -Wextra -Wpedantic
gcc ../aes-key-wrap.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-key-wrap.o -Wall -Wextra -Wpedantic
gcc ../straight-crypt.c ../../utils/utils.c -o straight-crypt.o -Wall -Wextra -Wpedantic
gcc ../lfsr_recovery_tool.c ../../utils/utils.c -o lfsr_recovery_tool.o -Wall -Wextra -Wpedantic
gcc ../lfsr_expansion_tool.c ../../utils/utils.c -o lfsr_expansion_tool.o -Wall -Wextra -Wpedantic