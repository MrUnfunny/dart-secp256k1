import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../generated/generated_bindings.dart';

void main() {
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
  var seckey2 = [
    0xff,
    0xba,
    0x10,
    0xfb,
    0x25,
    0x4d,
    0xb0,
    0x04,
    0xc7,
    0x60,
    0xfe,
    0x24,
    0x40,
    0x20,
    0x12,
    0xc6,
    0xae,
    0xc3,
    0xed,
    0x2e,
    0x7e,
    0xfb,
    0x7d,
    0x77,
    0x9a,
    0x53,
    0x3a,
    0x44,
    0x92,
    0xda,
    0xe1,
    0x8b,
  ];

  final ffi = NativeLibrary(
    DynamicLibrary.open(
      "/home/mohit/Desktop/dart-secp256k1/dart-secp256k1/trytest/build/libtap-protocol.so",
    ),
  );

  final Pointer<UnsignedChar> s1 = malloc.allocate(32);
  final Pointer<UnsignedChar> s2 = malloc.allocate(32);
  final Pointer<UnsignedChar> res = malloc.allocate(32);

  for (int i = 0; i < 32; i++) {
    s1[i] = seckey1[i];
    s2[i] = seckey2[i];
  }

  ffi.tryFunc(s1, s2, res);

  String finalResult = '';

  for (int i = 0; i < 32; i++) {
    finalResult += res.elementAt(i).value.toRadixString(16);
  }

  print('\n\nresult is $finalResult');

  malloc.free(s1);
  malloc.free(s2);
  malloc.free(res);
}
