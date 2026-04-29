import 'dart:typed_data';
import 'package:cbor/cbor.dart';

class CableParser {
  static Map<int, int> digitToByteCount = {
    17: 7, 16: 7,
    15: 6, 14: 6,
    13: 5, 12: 5, 11: 5,
    10: 4, 9: 4,
    8: 3, 7: 3, 6: 3,
    5: 2, 4: 2,
    3: 1, 2: 1, 1: 1
  };

  static Uint8List decodeUri(String uri) {
    if (uri.toLowerCase().startsWith('fido:/')) {
      uri = uri.substring(6);
    }
    
    List<int> bytes = [];
    for (int i = 0; i < uri.length; i += 17) {
      int end = i + 17;
      if (end > uri.length) end = uri.length;
      String chunk = uri.substring(i, end);
      
      BigInt num = BigInt.parse(chunk);
      int byteCount = digitToByteCount[chunk.length] ?? 7;
      
      List<int> chunkBytes = [];
      String hex = num.toRadixString(16).padLeft(byteCount * 2, '0');
      for (int j = 0; j < hex.length; j += 2) {
        chunkBytes.add(int.parse(hex.substring(j, j + 2), radix: 16));
      }
      bytes.addAll(chunkBytes.reversed);
    }
    
    return Uint8List.fromList(bytes);
  }

  static dynamic parseCbor(Uint8List bytes) {
    final decoded = cbor.decode(bytes);
    return decoded.toObject();
  }
}
