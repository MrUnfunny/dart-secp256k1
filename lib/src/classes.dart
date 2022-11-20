import 'package:dart_secp256k1/src/utils.dart';

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
