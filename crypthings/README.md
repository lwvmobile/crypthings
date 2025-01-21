# Crypthings Overview

## Secure Cipher Crypthings

aes-ofb-crypt, des56-ca-crypt, des56-ofb-crypt, tdea-tofb-crypt are cryptographically secure (or historically secure...ish in the case of single key DES56) message cipher programs that will allow a user to input hex octets to be ciphered, a key, an IV (initialization vector), keystream offset value, etc as applicable, in order to encrypt or decrypt the input hex octets to produce either cipher text, or plain text. The cipher operation performed is the same as the name of the program.

For Example, Using aes-ofb-crypt and the test vectors found on example F.4.5 on page 54 of [NIST 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf "NIST  800-38A") and using a keystream offset of 16 to account for the first round discard (IV round), we can reproduce the example cipher text values, and vice versa to recover the plain text.

```
./aes-ofb-crypt.o

----------------Tinier-AES OFB Message Cipher----------------
 Enter AES Key Len / Type (128/192/256): 256
 AES 256 

 Include any leading zeroes in key values, IV, and Input Message!
 Enter Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4

 Key: 603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4
 Enter IV (4, 8, or 16 octets): 000102030405060708090a0b0c0d0e0f

  IV Len: 16 Octets;
 IV(128): 000102030405060708090A0B0C0D0E0F

 Enter Keystream Application Offset (#Bytes, 0 and 16 are typical): 16
 Keystream Offset: 16

 Enter Input Message (Hex Octets): AE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710

  Input: AE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710

 Output: 4FEBDC6740D20B3A C88F6AD82A4FB08D 71AB47A086E86EED F39D1C5BBA97C408 0126141D67F37BE8 538F5A8BE740E484
 Enter any value to Exit: 1

```

The process for using DES56 and TDEA is similar. 

For Example, Using tdea-tofb-crypt and the test vectors found for OFB-TDES on page 26 of [TDEA Examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf "TDEA Examples"), we can reproduce the example cipher text values, and vice versa to recover the plain text.


```
./tdea-tofb-crypt.o

----------------TDEA (Triple DES) OFB Message Cipher----------------

 Include any leading zeroes in key values, IV, and Input Message!
 Enter Key K1 (8 octets): 0123456789ABCDEF
 K1: 0123456789ABCDEF
 Enter Key K2 (8 octets): 23456789ABCDEF01
 K2: 23456789ABCDEF01
 Enter Key K3 (8 octets): 456789ABCDEF0123
 K3: 456789ABCDEF0123
 Enter IV (8 octets): F69F2445DF4F9B17
 IV: F69F2445DF4F9B17
 Enter Keystream Application Offset (#Bytes, 0, 8, or 19 are typical): 0
 Keystream Offset: 0
 Enter Input Message (Hex Octets): 6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51

  Input: 6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51

 Output: 078BB74E59CE7ED6 267E120692667DA1 A58662D7E04CBC64 2144D55C03DB5AEE

 Enter any value to Exit: 1
```

Note: Using TDEA with the same key 3 times is the same as running DES56 single key.

## Simple/Weak Cipher Crypthings

straight-crypt, scrambler-crypt, and rc4-crypt crypthings use what are considered simple and/or weak cipher functions. Historically, they may have been used for simplicity, export limitation rules, cost saving measures, or low powered hardware or processing capability in real time.

Straight, as in, a static key value that is repeated on a bit length basis and applied directly to a plain or cipher text via exlusive OR (XOR) on a mod len basis. A "determined adversary" would have zero issue reversing this type of cipher with a known, partially know, or predictable plain text attack, with no more than a simple programming calculator with an XOR funcion.

```
./straight-crypt.o

----------------Straight XOR Message Cipher----------------
 Enter Key (Hex): 1234
 Key: 1234 
 Enter Number of Significant Bits in Key: 16
 Is this a 48/49-bit mode operation on 56-bit input? (0-no/1-yes): 0
 Apply Keystream Offset by number of bits (0-no/#bits): 0

 Include any leading zeroes in Input Message!

 Enter Input Message (Hex Octets): 123412341234123412341234

  Input: 123412341234123412341234
     KS: 123412341234123412341234
 Output: 000000000000000000000000
```

Scrambler is a key bit sequence created with an LFSR (linear feedback shift register) on selected taps and lengths, using the key value as the inital LFSR Seed value, and its keystream applied directly to a plain or cipher text. This cipher is not secure against modern brute force attacks when a plain text is known or can be moderately predicted. 

```
./scrambler-crypt.o 

----------------Scrambler Message Cipher----------------

 Include any leading zeroes in Input Message!
 Enter Key or Seed Value (hex): 1234
 Key: 1234 (4660)
 Enter Number of bits in Key/Seed (dec): 15
 Apply Keystream Offset by number of bits (0-no/#bits): 0
 Is this a 49-bit mode operation on 56-bit input? (0-no/1-yes): 0

 Enter Input Message (Hex Octets): 1234567890ABCDEF

  Input: 1234567890ABCDEF
     KS: 2C48E9B275AD3DEE
 Output: 3E7CBFCAE506F001

```

RC4 (a.k.a. ARC4, ADP, EP, or Wifi WEP Encryption) is a 40-bit key combined with a variable len IV to initialize and execute a simple byte swap sequence (mod 256) to produce a keystream to directly apply to plain or cipher text. Due to its short key length, this cipher is not secure againt modern brute force attacks, along with the aforementioned known or predictable plain text exploitation.

```
./rc4-crypt.o 

----------------RC4 Message Cipher----------------
 Enter RC4 IV Len (32 or 64 bits are typical):  32
 Enter RC4 Dropbyte Value (#Bytes, 256 and 267 are typical):  256
 Enter Keystream Application Offset (#Bytes, 0 is default):  0

 Include any leading zeroes in key values, IV, and Input Message!
 Enter Key (5 octets): 9deadbeef9
 Key: 9DEADBEEF9
 Enter IV (4 or 8 octets are typical): 12345678
 IV: 12345678
 KIV: 9DEADBEEF912345678
 Enter Input Message (Hex Octets): 0000000000000000000000000000000000000000000000000000000

  Input: 00000000000000000000000000000000000000000000000000000000

 Output: 273AB193908CBD3EB4B9FF41C2D4E234B967D01EE741FE31559FE4C7

 Enter any value to Exit: 
```

These functions should only be used to recover previously stored or pre-existing data, and are certainly not recommended to be used in any fashion for securely encrypting new data.

## Key Wrap Crypthings

aes-key-wrap, aes-key-unwrap, tdea-key-wrap, and tdea-key-unwrap (KW and TKW) are key wrapping programs that will take encryption keys of various length values (values determined by common key length values, or otherwise, multiples of one half the size of the cipher block, up to the key length of the cipher), and wrap or unwrap them by encrypting or decrypting them multiple times with a pre-shared private key and incorporating an integrety check value (0xA6A6A6...) and iterator permutations on input to produce a cipher text that can be transmitted and sent to another location or a plain text that can be recovered in a cryptographically secure way.

For example, a communication system may wish to re-key their equipment by sending a message including a key wrapped key (inner layer) with further instructions to the equipment. That message, in its entirety, may in turn, be encrypted as well (outer layer) with a second key for additional security.

For example, using aes-key-wrap and aes-key-unwrap and the test vectors found in example 1.6 on page 7, [Key Wrap Examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/key-wrapping-KW-KWP.pdf "Key Wrap Examples"), we can successfully wrap and unwrap a key of length 256 using a 256-bit AES key.

```
./aes-key-wrap.o 

------------AES Key Wrap Algorithm------------------------------
 Enter Key to Wrap Len / Type  (64/128/192/256): 256
 Enter AES Un/Wrap Key Len / Type (128/192/256): 256
 Enter Un/Wrap Key: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
 Enter Key to Wrap: 00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
 Cipher Text: 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
 Enter any value to Exit: 1

./aes-key-unwrap.o 

------------AES Key Unwrap Algorithm------------------------------
 Enter Key to Unwrap Len / Type  (64/128/192/256): 256
 Enter AES Un/Wrap Key Len / Type   (128/192/256): 256
 Enter Un/Wrap Key: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
 Enter Cipher Text: 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
 Plain Text: A6A6A6A6A6A6A6A600112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
 Unwrap Success!
 Unwrapped Key: 0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F
 Enter any value to Exit: 1

```

The work flow for TDEA (TKW) is similar.

For example, using tdea-key-wrap and tdea-key-unwrap and the test vectors found in example 3.1 on page 18, [Key Wrap Examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/key-wrapping-KW-KWP.pdf "Key Wrap Examples"), we can successfully wrap and unwrap a key of length 128 using TDEA.

```
./tdea-key-wrap.o 

------------TDEA Key Wrap Algorithm------------------------------
 Enter Key to Wrap Len / Type (64/128/192): 128
 Enter Key K1: 0001020304050607
 Enter Key K2: 08090A0B0C0D0E0F
 Enter Key K3: 1011121314151617
 Enter Key to Wrap: 00112233445566778899AABBCCDDEEFF
 Cipher Text: 75F5F26521D739BA33F9619B52D2AB0D29822081
 Enter any value to Exit: 1

./tdea-key-unwrap.o 

------------TDEA Key Unwrap Algorithm------------------------------
 Enter Key to Unwrap Len / Type (64/128/192): 128
 Enter Key K1: 0001020304050607
 Enter Key K2: 08090A0B0C0D0E0F
 Enter Key K3: 1011121314151617
 Enter Cipher Text: 75F5F26521D739BA33F9619B52D2AB0D29822081
 Plain Text: A6A6A6A600112233445566778899AABBCCDDEEFF
 Unwrap Success!
 Unwrapped Key: 00112233 44556677 8899AABB CCDDEEFF
 Enter any value to Exit: 1
```

Note: Key Wrap Crypthings can only wrap or unwrap one key at a time.

## LFSR Tools Crypthings

lfsr-expansion-tool can be used to expand an IV of certain pre-selected length values (32, 64) to larger sizes (64, 128) that are suitable to be used as IVs for cipher functions whose block sizes are of the same length. Users can also input a number of times, or iterations, to progressively create new IVs for subsequent encryption sessions, if needed.

lfsr-recovery-tool can be used to either further iterate an IV of a selected length, or to run an LFSR of a selected legnth in a reverse direction, if recovery of a previous IV is needed for an encryption session.

```
./lfsr-expansion-tool.o 

----------------LFSR Expansion Tool----------------

 Include any leading zeroes!
 LFSR Tap Configuration (32/64): 32
 LFSR Max Size (32/64/128): 128
 Enter LFSR Value: 12345678
 LFSR: 12345678
 How Many Times? (up to 65535): 5
 ITER: 0001;
 IV(128): 12345678B451463A41D78991A49A6402
 ITER: 0002;
 IV(128): B451463A41D78991A49A640267633CC9
 ITER: 0003;
 IV(128): 41D78991A49A640267633CC93976CD8B
 ITER: 0004;
 IV(128): A49A640267633CC93976CD8BEEB6582C
 ITER: 0005;
 IV(128): 67633CC93976CD8BEEB6582C291E560D

```

```
./lfsr-recovery-tool.o 

----------------LFSR Recovery Tool----------------

 Include any leading zeroes!
 LFSR Tap Configuration (32/64): 32
 Enter LFSR Value: 12345678
 LFSR: 12345678
 LFSR Increment: 32
 How Many Times? (up to 65535): 5
 Direction? (0-reverse/1-forward): 1

 ITER: 0001; LFSR32D(32): B468E067
 ITER: 0002; LFSR32D(32): 0567456B
 ITER: 0003; LFSR32D(32): 6998F7EE
 ITER: 0004; LFSR32D(32): 0BD18C25
 ITER: 0005; LFSR32D(32): 1D50AD9A

 Enter any value to Exit: 1

./lfsr-recovery-tool.o 

----------------LFSR Recovery Tool----------------

 Include any leading zeroes!
 LFSR Tap Configuration (32/64): 32
 Enter LFSR Value: 1D50AD9A
 LFSR: 1D50AD9A
 LFSR Increment: 32
 How Many Times? (up to 65535): 5
 Direction? (0-reverse/1-forward): 0

 ITER: 0001; RV LFSR32D(32): 0BD18C25
 ITER: 0002; RV LFSR32D(32): 6998F7EE
 ITER: 0003; RV LFSR32D(32): 0567456B
 ITER: 0004; RV LFSR32D(32): B468E067
 ITER: 0005; RV LFSR32D(32): 12345678

 Enter any value to Exit: 1

```

