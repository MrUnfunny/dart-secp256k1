import 'dart:ffi';

import 'package:dart_secp256k1/src/utils.dart';
import 'package:ffi/ffi.dart';

import '../generated/generated_bindings.dart' as ffi;
import 'classes.dart';

class Secp256k1 {
  ffi.secp256k1 secp;

  Secp256k1(DynamicLibrary dynamicLibrary)
      : secp = ffi.secp256k1(dynamicLibrary);
  //: secp = NativeLibrary(
  //   (Platform.isIOS)
  //       ? DynamicLibrary.process()
  //       : DynamicLibrary.open(
  //           (Platform.isMacOS)
  //               ? path.join(
  //                   Directory.current.path,
  //                   "native",
  //                   "build",
  //                   "libsecp256k1.dylib",
  //                 )
  //               : Platform.isWindows
  //                   ? path.join(
  //                       Directory.current.path,
  //                       "native",
  //                       "build",
  //                       "libsecp256k1.dll",
  //                     )
  //                   : path.join(
  //                       Directory.current.path,
  //                       "native",
  //                       "build",
  //                       "libsecp256k1.so",
  //                     ),
  //         ),
  // );

  List<int> ecdh(List<int> privateKey, Secp256k1PublicKey publicKey) {
    if (privateKey.length != 32) {
      throw Exception('Private Key must be 32 bytes only');
    }

    List<int> sharedSecret = List<int>.filled(32, 0);

    final pubKeyX = bigIntToUintList(publicKey.X).reversed.toList();
    final pubKeyY = bigIntToUintList(publicKey.Y).reversed.toList();

    final Pointer<UnsignedChar> secretKeyList = malloc.allocate(32);
    final Pointer<UnsignedChar> publicKeyList = malloc.allocate(64);
    final Pointer<UnsignedChar> res = malloc.allocate(32);

    for (int i = 0; i < 32; i++) {
      secretKeyList[i] = privateKey[i];
      publicKeyList[i] = pubKeyX[i];
      publicKeyList[32 + i] = pubKeyY[i];
    }

    secp.ecdh(secretKeyList, publicKeyList, res);

    for (int i = 0; i < 32; i++) {
      sharedSecret[i] = res[i];
    }

    malloc.free(secretKeyList);
    malloc.free(publicKeyList);
    malloc.free(res);

    return sharedSecret;
  }

  List<int> ecdsaRecover(List<int> signature, List<int> msgHash, int recId) {
    if (signature.length != 64) {
      throw Exception('Signature Length must be 64 bytes only');
    }
    if (msgHash.length != 32) {
      throw Exception('Message hash must be 32 bytes only');
    }

    List<int> resPubKey = List<int>.filled(33, 0);

    final Pointer<UnsignedChar> signatureNative = malloc.allocate(64);
    final Pointer<UnsignedChar> msgHashNative = malloc.allocate(32);

    final Pointer<UnsignedChar> res = malloc.allocate(33);

    for (int i = 0; i < 32; i++) {
      msgHashNative[i] = msgHash[i];
    }

    for (int i = 0; i < 64; i++) {
      signatureNative[i] = signature[i];
    }

    int ecdsaRes =
        secp.ecdsaRecover(res, msgHashNative, signatureNative, recId);
    print(ecdsaRes);

    for (int i = 0; i < 33; i++) {
      resPubKey[i] = res[i];
    }

    malloc.free(signatureNative);
    malloc.free(msgHashNative);
    malloc.free(res);

    return resPubKey;
  }
}
