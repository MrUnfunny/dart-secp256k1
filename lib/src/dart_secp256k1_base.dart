import 'dart:ffi';

import 'package:dart_secp256k1/src/utils.dart';
import 'package:ffi/ffi.dart';

import '../generated/generated_bindings.dart';
import 'classes.dart';

class Secp256k1 {
  NativeLibrary ffi;

  Secp256k1(DynamicLibrary dynamicLibrary)
      : ffi = NativeLibrary(dynamicLibrary);
  //: ffi = NativeLibrary(
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

    ffi.ecdh(secretKeyList, publicKeyList, res);

    for (int i = 0; i < 32; i++) {
      sharedSecret[i] = res[i];
    }

    malloc.free(secretKeyList);
    malloc.free(publicKeyList);
    malloc.free(res);

    return sharedSecret;
  }

  List<int> ecdhRecover(List<int> signature, List<int> msgHash) {
    List<int> resPubKey = List<int>.filled(33, 0);

    final Pointer<UnsignedChar> signatureNative = malloc.allocate(65);
    final Pointer<UnsignedChar> msgHashNative = malloc.allocate(32);

    final Pointer<UnsignedChar> res = malloc.allocate(32);

    for (int i = 0; i < 32; i++) {
      msgHashNative[i] = msgHash[i];
    }

    for (int i = 0; i < 65; i++) {
      signatureNative[i] = signature[i];
    }

    ffi.CT_sig_to_pubkey(res, msgHashNative, signatureNative);

    for (int i = 0; i < 33; i++) {
      resPubKey[i] = res[i];
    }

    malloc.free(signatureNative);
    malloc.free(msgHashNative);
    malloc.free(res);

    return resPubKey;
  }
}
