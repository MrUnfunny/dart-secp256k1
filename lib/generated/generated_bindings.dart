// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
import 'dart:ffi' as ffi;

/// dart bindings for secp256k1.
class secp256k1 {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  secp256k1(ffi.DynamicLibrary dynamicLibrary)
      : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  secp256k1.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  void ecdh(
    ffi.Pointer<ffi.UnsignedChar> secretKey,
    ffi.Pointer<ffi.UnsignedChar> pubKey,
    ffi.Pointer<ffi.UnsignedChar> sharedSecret,
  ) {
    return _ecdh(
      secretKey,
      pubKey,
      sharedSecret,
    );
  }

  late final _ecdhPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Pointer<ffi.UnsignedChar>)>>('ecdh');
  late final _ecdh = _ecdhPtr.asFunction<
      void Function(ffi.Pointer<ffi.UnsignedChar>,
          ffi.Pointer<ffi.UnsignedChar>, ffi.Pointer<ffi.UnsignedChar>)>();

  void CT_sig_to_pubkey(
    ffi.Pointer<ffi.UnsignedChar> resPubKey,
    ffi.Pointer<ffi.UnsignedChar> msgHash,
    ffi.Pointer<ffi.UnsignedChar> signature,
  ) {
    return _CT_sig_to_pubkey(
      resPubKey,
      msgHash,
      signature,
    );
  }

  late final _CT_sig_to_pubkeyPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Pointer<ffi.UnsignedChar>)>>('CT_sig_to_pubkey');
  late final _CT_sig_to_pubkey = _CT_sig_to_pubkeyPtr.asFunction<
      void Function(ffi.Pointer<ffi.UnsignedChar>,
          ffi.Pointer<ffi.UnsignedChar>, ffi.Pointer<ffi.UnsignedChar>)>();

  int ecdsaRecover(
    ffi.Pointer<ffi.UnsignedChar> resPubKey,
    ffi.Pointer<ffi.UnsignedChar> msgHash,
    ffi.Pointer<ffi.UnsignedChar> signature,
    int rec_id,
  ) {
    return _ecdsaRecover(
      resPubKey,
      msgHash,
      signature,
      rec_id,
    );
  }

  late final _ecdsaRecoverPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int Function(
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Pointer<ffi.UnsignedChar>,
              ffi.Int)>>('ecdsaRecover');
  late final _ecdsaRecover = _ecdsaRecoverPtr.asFunction<
      int Function(ffi.Pointer<ffi.UnsignedChar>, ffi.Pointer<ffi.UnsignedChar>,
          ffi.Pointer<ffi.UnsignedChar>, int)>();
}