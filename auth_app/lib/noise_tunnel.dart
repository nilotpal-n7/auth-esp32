import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:cryptography/cryptography.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

class NoiseTunnel {
  final List<int> hostPublicKey;
  final List<int> qrSecret;
  WebSocketChannel? _channel;

  NoiseTunnel({required this.hostPublicKey, required this.qrSecret});

  Future<void> connect() async {
    try {
      debugPrint("[Tunnel] Starting connect()");
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 16);
      debugPrint("[Tunnel] HKDF initialized");
      
      final secretKey = SecretKey(qrSecret);
      debugPrint("[Tunnel] SecretKey created");

      final derivedKey = await hkdf.deriveKey(
        secretKey: secretKey,
        info: 'cable v2 tunnel ID'.codeUnits,
      );
      debugPrint("[Tunnel] HKDF derivation complete");

      final tunnelIdBytes = await derivedKey.extractBytes();
      final tunnelIdBase64 = base64Url.encode(tunnelIdBytes).replaceAll('=', '');
      debugPrint("[Tunnel] Tunnel ID: $tunnelIdBase64");
      
      final wsUrl = Uri.parse('wss://cable.ua5v.com/cable/contact/$tunnelIdBase64');
      debugPrint("[Tunnel] Connecting to $wsUrl");

      _channel = WebSocketChannel.connect(wsUrl, protocols: ['fido.cable']);
      debugPrint("[Tunnel] WebSocket initialized");

    // 3. Listen for incoming encrypted messages from the Desktop Browser
    _channel!.stream.listen(
      (message) {
        debugPrint("Received Encrypted CTAP Packet from Cloud: ${message.length} bytes");
        // TODO: Implement Noise_KNpsk0_25519_AESGCM_SHA256 decryption here
      },
      onError: (error) {
        debugPrint("WebSocket Error: $error");
      },
      onDone: () {
        debugPrint("WebSocket Closed");
      },
    );
    } catch (e, stackTrace) {
      debugPrint("NoiseTunnel Exception: $e\n$stackTrace");
    }
  }

  void disconnect() {
    _channel?.sink.close();
  }
}
