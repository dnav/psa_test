# Building

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j 4
```

# Running

```
./psa_test
```

# Output

```
$ ./psa_test
Uncompressed key according to mbedtls_ecp_decompress(): 65 bytes
  04 0B 69 FE  B8 01 EB 90  33 1E E2 A6  5C CB B8 65   |..i.....3...\..e|
  BD 3D 44 3E  DC DF 2A 11  6D 0E 66 7B  C3 46 60 93   |.=D>..*.m.f{.F`.|
  8C 97 49 70  EE 28 17 55  10 24 5C C2  4F 92 DB F0   |..Ip.(.U.$\.O...|
  97 E2 C0 AE  02 C4 D8 DE  9A A0 39 4C  CB 08 14 56   |..........9L...V|
  5C                                                   |\|

psa_raw_key_agreement() result: 32 bytes
  D0 45 B4 67  E9 1C 6A C7  64 58 7A 13  D1 E9 17 28   |.E.g..j.dXz....(|
  EA 6E 1C 1C  19 05 23 5F  CA A6 03 0A  D3 41 AB 19   |.n....#_.....A..|

Uncompressed key according to mbedtls_ecp_sw_derive_y(): 65 bytes
  04 0B 69 FE  B8 01 EB 90  33 1E E2 A6  5C CB B8 65   |..i.....3...\..e|
  BD 3D 44 3E  DC DF 2A 11  6D 0E 66 7B  C3 46 60 93   |.=D>..*.m.f{.F`.|
  8C 14 CF FB  9E 68 E7 28  91 75 38 E8  D7 05 7E 64   |.....h.(.u8...~d|
  CB D5 3C DE  9C 52 83 CF  4C 30 83 EA  0B 87 C1 DA   |..<..R..L0......|
  73                                                   |s|

psa_raw_key_agreement() failed (-135).
```

