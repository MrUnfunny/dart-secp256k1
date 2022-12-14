import 'dart:ffi';

import 'package:dart_secp256k1/dart_secp256k1.dart';

int recIdFromHeader(header) {
  var headerNum = header & 0xff;
  if (headerNum >= 39) {
    headerNum -= 12;
  } else if (headerNum >= 35) {
    headerNum -= 8;
  } else if (headerNum >= 31) {
    headerNum -= 4;
  }
  final recId = headerNum - 27;
  return recId;
}

void main() {
  final secp = Secp256k1(
    DynamicLibrary.open(
      "/Users/mohitsingh/Desktop/rnd/dart-secp256k1/native/build/libsecp256k1.dylib",
    ),
  );
  final sig = [
    0x20,
    0xaa,
    0x14,
    0xea,
    0x57,
    0x40,
    0x75,
    0xba,
    0x59,
    0x7b,
    0x8c,
    0x4,
    0x51,
    0xba,
    0xe7,
    0xef,
    0xc2,
    0x7,
    0xca,
    0x4c,
    0x6f,
    0x10,
    0x2,
    0xf7,
    0xa8,
    0xf7,
    0x2d,
    0x76,
    0xc1,
    0x32,
    0x4b,
    0x14,
    0x64,
    0x66,
    0x1b,
    0x53,
    0xbb,
    0x8e,
    0xa6,
    0x55,
    0xe3,
    0x7d,
    0x43,
    0x80,
    0xe9,
    0x7b,
    0x2,
    0xae,
    0xc9,
    0xba,
    0x44,
    0x3,
    0x18,
    0xe,
    0xb6,
    0xa,
    0x66,
    0xd8,
    0x6f,
    0x45,
    0x15,
    0xc5,
    0x52,
    0x45,
    0x3c
  ];
  final msgHash = [
    0x44,
    0x5f,
    0xc,
    0x7f,
    0xcd,
    0x9b,
    0x4f,
    0x31,
    0xb8,
    0xee,
    0xa8,
    0x5b,
    0xd5,
    0xb7,
    0x8c,
    0x48,
    0x23,
    0x60,
    0x9c,
    0x85,
    0xa0,
    0xd3,
    0x54,
    0xbd,
    0x45,
    0x84,
    0x69,
    0x31,
    0x2f,
    0x90,
    0x77,
    0xe4,
  ];

  final recId = recIdFromHeader(sig.first);
  final resPubKey = secp.ecdsaRecover(sig.sublist(1), msgHash, recId);

  var seckey1 = [
    0xd7,
    0xfe,
    0x9b,
    0x49,
    0xd0,
    0x63,
    0x1e,
    0x36,
    0x82,
    0x8c,
    0xbc,
    0xc7,
    0xf4,
    0xaf,
    0x8b,
    0x29,
    0x3e,
    0x44,
    0x3c,
    0xa8,
    0x40,
    0xdf,
    0xb8,
    0x9a,
    0xef,
    0x4f,
    0x4a,
    0xb0,
    0x5e,
    0x1f,
    0xb3,
    0x07,
  ];
  // var seckey2 = [
  //   0xff,
  //   0xba,
  //   0x10,
  //   0xfb,
  //   0x25,
  //   0x4d,
  //   0xb0,
  //   0x04,
  //   0xc7,
  //   0x60,
  //   0xfe,
  //   0x24,
  //   0x40,
  //   0x20,
  //   0x12,
  //   0xc6,
  //   0xae,
  //   0xc3,
  //   0xed,
  //   0x2e,
  //   0x7e,
  //   0xfb,
  //   0x7d,
  //   0x77,
  //   0x9a,
  //   0x53,
  //   0x3a,
  //   0x44,
  //   0x92,
  //   0xda,
  //   0xe1,
  //   0x8b,
  // ];
  var pubKeyHex =
      "043b5ac2b005c78297272c0f5dbeefd88cec42db09392ac7cb1e2c64689ca1fe634631916ee95dbd892ffeda37e31d04689aa1715fa1c7dc6f8a5fcdf20c3ffa78";

  final secret = secp.ecdh(
    seckey1,
    Secp256k1PublicKey.fromHex(pubKeyHex),
  );

  print('res pub key is $resPubKey');
  print('secret is $secret');

  return;
}
