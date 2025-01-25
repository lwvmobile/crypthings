#! /bin/bash
#
/usr/bin/x86_64-w64-mingw32-gcc ../rc4-crypt.c ../../ciphers/rc4/rc4.c ../../utils/utils.c -o rc4-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../aes-ofb-crypt.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-ofb-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../aes-ctr-crypt.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-ctr-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../des56-ofb-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o des56-ofb-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../des56-ca-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o des56-ca-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../tdea-tofb-crypt.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-tofb-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../scrambler-crypt.c ../../ciphers/scrambler/scrambler.c ../../utils/utils.c -o scrambler-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../aes-key-unwrap.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-key-unwrap.exe
/usr/bin/x86_64-w64-mingw32-gcc ../aes-key-wrap.c ../../ciphers/aes/aes.c ../../utils/utils.c -o aes-key-wrap.exe
/usr/bin/x86_64-w64-mingw32-gcc ../tdea-key-wrap.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-key-wrap.exe
/usr/bin/x86_64-w64-mingw32-gcc ../tdea-key-unwrap.c ../../ciphers/des/des.c ../../utils/utils.c -o tdea-key-unwrap.exe
/usr/bin/x86_64-w64-mingw32-gcc ../straight-crypt.c ../../utils/utils.c -o straight-crypt.exe
/usr/bin/x86_64-w64-mingw32-gcc ../lfsr-recovery-tool.c ../../utils/utils.c -o lfsr-recovery-tool.exe
/usr/bin/x86_64-w64-mingw32-gcc ../lfsr-expansion-tool.c ../../utils/utils.c -o lfsr-expansion-tool.exe