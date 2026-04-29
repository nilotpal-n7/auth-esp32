import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'cable_parser.dart';

void main() {
  FlutterBluePlus.setLogLevel(LogLevel.verbose, color: true);
  runApp(const AuthProxyApp());
}

class AuthProxyApp extends StatelessWidget {
  const AuthProxyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FIDO caBLE Proxy',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const BleScannerScreen(),
    );
  }
}

class BleScannerScreen extends StatefulWidget {
  const BleScannerScreen({super.key});

  @override
  State<BleScannerScreen> createState() => _BleScannerScreenState();
}

class _BleScannerScreenState extends State<BleScannerScreen> {
  List<ScanResult> _scanResults = [];
  bool _isScanning = false;
  late StreamSubscription<List<ScanResult>> _scanResultsSubscription;
  late StreamSubscription<bool> _isScanningSubscription;

  BluetoothDevice? _esp32Device;
  final TextEditingController _macController = TextEditingController();

  @override
  void initState() {
    super.initState();

    _scanResultsSubscription = FlutterBluePlus.scanResults.listen((results) {
      if (!mounted) return;
      setState(() {
        _scanResults = results;
        // Auto-connect if we find our ESP32
        for (var r in results) {
          final deviceName = r.device.advName.isNotEmpty
              ? r.device.advName
              : r.device.platformName;
          if (deviceName == 'AuthKey-ESP32' && _esp32Device == null) {
            _connectToDevice(r.device);
          }
        }
      });
    });

    _isScanningSubscription = FlutterBluePlus.isScanning.listen((state) {
      if (!mounted) return;
      setState(() {
        _isScanning = state;
      });
    });
  }

  @override
  void dispose() {
    _scanResultsSubscription.cancel();
    _isScanningSubscription.cancel();
    _macController.dispose();
    super.dispose();
  }

  void _connectByMac() {
    final mac = _macController.text.trim();
    if (mac.isNotEmpty) {
      final device = BluetoothDevice.fromId(mac);
      _connectToDevice(device);
    }
  }

  Future<void> _startScan() async {
    try {
      if (await FlutterBluePlus.isSupported == false) {
        return;
      }

      var adapterState = await FlutterBluePlus.adapterState.first;
      if (adapterState != BluetoothAdapterState.on) {
        return;
      }

      await FlutterBluePlus.startScan(timeout: const Duration(seconds: 15));
    } catch (e) {
      debugPrint("Error starting scan: $e");
    }
  }

  Future<void> _stopScan() async {
    await FlutterBluePlus.stopScan();
  }

  Future<void> _connectToDevice(BluetoothDevice device) async {
    setState(() => _esp32Device = device);
    await _stopScan();

    try {
      await device.connect();
      debugPrint("Connected to ${device.platformName}");
      if (mounted) {
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (context) => QrScannerScreen(device: device),
          ),
        );
      }
    } catch (e) {
      setState(() => _esp32Device = null);
      debugPrint("Failed to connect: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Connect to ESP32'),
        actions: [
          if (_isScanning)
            IconButton(icon: const Icon(Icons.stop), onPressed: _stopScan)
          else
            IconButton(icon: const Icon(Icons.refresh), onPressed: _startScan),
        ],
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            if (_esp32Device != null) ...[
              const Icon(
                Icons.bluetooth_connected,
                size: 64,
                color: Colors.green,
              ),
              const SizedBox(height: 16),
              Text(
                'Connected to ${_esp32Device!.platformName}',
                style: Theme.of(context).textTheme.titleLarge,
              ),
            ] else ...[
              Icon(
                _isScanning ? Icons.bluetooth_searching : Icons.bluetooth,
                size: 64,
                color: _isScanning ? Colors.blue : Colors.grey,
              ),
              const SizedBox(height: 16),
              Text(
                _isScanning
                    ? 'Scanning for AuthKey-ESP32...'
                    : 'Tap refresh to scan',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 32.0),
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _macController,
                        decoration: const InputDecoration(
                          labelText: 'Or enter MAC Address',
                          hintText: 'e.g. 00:11:22:33:44:55',
                          border: OutlineInputBorder(),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    ElevatedButton(
                      onPressed: _connectByMac,
                      child: const Text('Connect'),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              if (_scanResults.isNotEmpty)
                Expanded(
                  child: ListView.builder(
                    itemCount: _scanResults.length,
                    itemBuilder: (context, index) {
                      final r = _scanResults[index];
                      final deviceName = r.device.advName.isNotEmpty
                          ? r.device.advName
                          : r.device.platformName;
                      return ListTile(
                        title: Text(
                          deviceName.isEmpty ? 'Unknown Device' : deviceName,
                        ),
                        subtitle: Text(r.device.remoteId.toString()),
                        trailing: ElevatedButton(
                          onPressed: () => _connectToDevice(r.device),
                          child: const Text('Connect'),
                        ),
                      );
                    },
                  ),
                ),
            ],
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _startScan,
        child: const Icon(Icons.search),
      ),
    );
  }
}

class QrScannerScreen extends StatefulWidget {
  final BluetoothDevice device;
  const QrScannerScreen({super.key, required this.device});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen> {
  final MobileScannerController _scannerController = MobileScannerController();
  bool _hasScanned = false;

  @override
  void dispose() {
    _scannerController.dispose();
    super.dispose();
  }

  Future<void> _onDetectUri(String uri) async {
    if (_hasScanned) return;
    setState(() => _hasScanned = true);
    try { _scannerController.stop(); } catch (_) {}
    
    debugPrint('Found FIDO URI: $uri');
    
    String parsedText = "";
    try {
      final bytes = CableParser.decodeUri(uri);
      final cborMap = CableParser.parseCbor(bytes);
      parsedText = cborMap.toString();
      debugPrint("Parsed CBOR: $parsedText");

      // Extract keys and start the tunnel
      final hostPubKey = List<int>.from(cborMap[0]);
      final qrSecret = List<int>.from(cborMap[1]);
      
      // Combine them into a single payload for the ESP32
      // Add the 3-byte CTAP INIT header: [CMD=0xBF, LEN_HI=0x00, LEN_LO=0x31 (49)]
      final espPayload = <int>[
        0xBF, 0x00, 0x31,
        ...hostPubKey, 
        ...qrSecret
      ];
      
      // Send to ESP32 over BLE
      bool wroteKeys = false;
      final StringBuffer debugLog = StringBuffer();

      // Our private provisioning service UUID (avoids Android FIDO interception)
      const provServiceUuid = 'a3c87500-8ed3-4bdf-8a39-a01bebede295';
      const provWriteUuid   = 'a3c87501-8ed3-4bdf-8a39-a01bebede295';

      try {
        // Step 1: Ensure we're connected
        if (!widget.device.isConnected) {
          debugLog.writeln("Reconnecting...");
          await widget.device.connect(autoConnect: false, timeout: const Duration(seconds: 10));
          await Future.delayed(const Duration(milliseconds: 500));
        }
        debugLog.writeln("Connected: ${widget.device.isConnected}");

        // Step 2: Discover services
        final services = await widget.device.discoverServices();
        debugLog.writeln("Found ${services.length} services:");

        BluetoothCharacteristic? targetChar;
        for (var service in services) {
          final sUuid = service.uuid.str.toLowerCase();
          debugLog.writeln("SVC: $sUuid");
          for (var char in service.characteristics) {
            final cUuid = char.uuid.str.toLowerCase();
            debugLog.writeln("  CHR: $cUuid");
            if (sUuid == provServiceUuid && cUuid == provWriteUuid) {
              targetChar = char;
              debugLog.writeln("  >>> MATCH (provisioning char)");
            }
          }
        }

        if (targetChar == null) {
          throw Exception("Provisioning characteristic not found!\n$debugLog");
        }

        debugLog.writeln("Writing ${espPayload.length} bytes...");
        await targetChar.write(espPayload, withoutResponse: true);

        wroteKeys = true;
        debugLog.writeln("Write OK!");

        // CRITICAL: We must disconnect so the ESP32 is free to accept
        // Chrome's incoming connection for the Noise handshake!
        await widget.device.disconnect();
        debugLog.writeln("Disconnected from device.");

      } catch (bleErr) {
        debugLog.writeln("ERROR: $bleErr");
        debugPrint("BLE Send Error: $bleErr");
        if (!mounted) return;
        final errorText = debugLog.toString();
        showDialog(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('BLE Error'),
            content: SingleChildScrollView(child: SelectableText(errorText)),
            actions: [
              TextButton(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: errorText));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Copied to clipboard!'))
                  );
                },
                child: const Text('Copy'),
              ),
              TextButton(onPressed: () => Navigator.pop(context), child: const Text('OK')),
            ],
          ),
        );
        return;
      }
      
      if (!mounted) return;

      // Show success dialog
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('FIDO Proxy Active'),
          content: Text('Sent keys to ESP32!\n\nPublic Key: ${hostPubKey.length} bytes\nSecret: ${qrSecret.length} bytes'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('OK'),
            ),
          ],
        ),
      );

    } catch (e, st) {
      debugPrint("Synchronous extraction error: $e\n$st");
      parsedText = "Failed to parse: $e";
      
      if (!mounted) return;
      // Show error dialog
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('FIDO QR Error'),
          content: Text('Failed to parse: \n$parsedText'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('OK'),
            ),
          ],
        ),
      );
    }
  }

  void _onDetect(BarcodeCapture capture) {
    if (_hasScanned) return;
    for (final barcode in capture.barcodes) {
      if (barcode.rawValue != null && barcode.rawValue!.startsWith('FIDO:/')) {
        _onDetectUri(barcode.rawValue!);
        break;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan FIDO Passkey QR')),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: TextField(
              decoration: const InputDecoration(
                labelText: 'Paste FIDO:/ URI manually (Linux Fallback)',
                hintText: 'FIDO:/123456...',
                border: OutlineInputBorder(),
              ),
              onSubmitted: (value) {
                if (value.startsWith('FIDO:/') || value.startsWith('fido:/')) {
                  _onDetectUri(value);
                }
              },
            ),
          ),
          if (!Platform.isLinux)
            Expanded(
              child: MobileScanner(
                controller: _scannerController, 
                onDetect: _onDetect,
              ),
            ),
          if (Platform.isLinux)
            const Expanded(
              child: Center(
                child: Padding(
                  padding: EdgeInsets.all(32.0),
                  child: Text(
                    'Camera scanning is not supported on Linux.\nPlease scan the FIDO QR code with your phone\'s camera, copy the FIDO:/... text, and paste it into the box above.',
                    textAlign: TextAlign.center,
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
