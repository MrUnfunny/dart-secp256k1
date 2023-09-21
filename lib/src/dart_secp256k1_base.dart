import 'dart:ffi';

import 'package:dart_secp256k1/src/utils.dart';
import 'package:ffi/ffi.dart';

import '../generated/generated_bindings.dart' as ffi;

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

class PrivateKey {
  late BigInt D;

  /// get the unique public key of the private key on secp256k1 curve
  Secp256k1PublicKey get publicKey {
    final point = getPointByBig(D, secp256k1.p, secp256k1.a, secp256k1.G);

    return Secp256k1PublicKey(point[0], point[1]);
  }

  /// generate a private key from random number
  PrivateKey(this.D);

  /// generate a private key from random number
  PrivateKey.generate() {
    D = getPrivKeyByRand(secp256k1.n);
  }

  /// convert a hex string to a private key(bigint)
  PrivateKey.fromHex(String hexString) {
    D = BigInt.parse(hexString, radix: 16);
  }

  /// generate a hex string from a private key(bigint)
  String toHex() {
    return D.toRadixString(16).padLeft(64, '0');
  }

  @override
  bool operator ==(other) {
    return other is PrivateKey && (D == other.D);
  }
}

class Secp256k1PublicKey {
  late BigInt X;
  late BigInt Y;

  Secp256k1PublicKey(this.X, this.Y);

  /// convert a hex string to a public key
  Secp256k1PublicKey.fromHex(String hexString) {
    final point = hex2Point(hexString);
    X = point[0];
    Y = point[1];
  }

  /// convert a compressed hex string to a public key(List of 2 bigints)
  Secp256k1PublicKey.fromCompressedHex(String hexString) {
    final point = hex2PointFromCompress(hexString);
    X = point[0];
    Y = point[1];
  }

  /// generate a hex string from a public key
  String toHex() {
    return point2Hex([X, Y]);
  }

  /// generate a compressed hex string from a public key
  String toCompressedHex() {
    return point2HexInCompress([X, Y]);
  }

  @override
  String toString() {
    return toHex();
  }

  @override
  bool operator ==(other) {
    return other is Secp256k1PublicKey && (X == other.X && Y == other.Y);
  }
}
