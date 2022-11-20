import 'dart:ffi';

import 'package:dart_secp256k1/src/utils.dart';
import 'package:ffi/ffi.dart';

import '../generated/generated_bindings.dart';
import 'classes.dart';

class Secp256k1 {
  final ffi = NativeLibrary(
    DynamicLibrary.open(
      "native/build/libsecp256k1.so",
    ),
  );

  String ecdh(List<int> privateKey, Secp256k1PublicKey publicKey) {
    String result = '';

    final pubKeyX = bigIntToByteData(publicKey.X).reversed.toList();
    final pubKeyY = bigIntToByteData(publicKey.Y).reversed.toList();

    final Pointer<UnsignedChar> secretKeyList = malloc.allocate(32);
    final Pointer<UnsignedChar> publicKeyList = malloc.allocate(64);
    final Pointer<UnsignedChar> res = malloc.allocate(32);

    for (int i = 0; i < 32; i++) {
      secretKeyList[i] = privateKey[i];
      publicKeyList[i] = pubKeyX[i];
      publicKeyList[32 + i] = pubKeyY[i];
    }

    ffi.ecdh(secretKeyList, publicKeyList, res);

    for (int i = 0; i < 32; i++) {
      result += res[i].toRadixString(16);
    }

    malloc.free(secretKeyList);
    malloc.free(publicKeyList);
    malloc.free(res);

    return result;
  }
}
