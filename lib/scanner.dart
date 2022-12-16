import "dart:io";
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

class Scanner extends StatefulWidget {
  const Scanner({Key? key}) : super(key: key);

  @override
  _ScannerState createState() => _ScannerState();
}

class _ScannerState extends State<Scanner> {
  final GlobalKey qrKey = GlobalKey(debugLabel: 'QR');
  var scannedData = 'Scan a code';
  Barcode? result;
  late int mode;

  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    //controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text("Scanner"),
      ),
      body: Stack(
        children: [
          Column(
            children: <Widget>[
              Expanded(
                flex: 5,
                child: Stack(
                  children: [
                    MobileScanner(
                      onDetect: (barcode, args) {
                        print(barcode.rawValue);
                        setState(() {
                          result = barcode;
                        });
                      },
                    ),
                    Center(
                      child: Container(
                        width: 300,
                        height: 300,
                        decoration: BoxDecoration(
                          border: Border.all(
                            color: result != null ? Colors.green : Colors.red,
                            width: 4,
                          ),
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                    )
                  ],
                ),
              ),
              Expanded(
                flex: 5,
                child: SingleChildScrollView(
                  child: Center(
                    child: (result != null)
                        ? Column(
                            children: [
                              Text('Participant id: ${result!.rawValue}'),
                              RawMaterialButton(
                                  onPressed: () {
                                    Navigator.pop(context, result!.rawValue);
                                  },
                                  child: Text(
                                    "Accept",
                                    style: TextStyle(
                                        fontWeight: FontWeight.bold,
                                        color: Colors.green),
                                  ),
                                  shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(18.0),
                                      side: BorderSide(
                                          width: 2, color: Colors.green))),
                            ],
                          )
                        : Text('Scan a code'),
                  ),
                ),
              )
            ],
          ),
        ],
      ),
    );
  }
}
