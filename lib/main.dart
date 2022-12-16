import 'dart:async';
import 'dart:convert';

import 'package:asymmetric_crypto_primitives/asymmetric_crypto_primitives.dart';
import 'package:asymmetric_crypto_primitives/ed25519_signer.dart';
import 'package:dkms_demo_multisig/scanner.dart';
import 'package:flutter/material.dart';
import 'package:keri/keri.dart' hide Action;
import 'package:path_provider/path_provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:dkms_demo_multisig/enums.dart';

void main() async{
  WidgetsFlutterBinding.ensureInitialized();
  var signer = await AsymmetricCryptoPrimitives.establishForEd25519();
  runApp(MaterialApp(home: MyApp(signer: signer,),debugShowCheckedModeBanner: false,));
}

class MyApp extends StatefulWidget {
  final Ed25519Signer signer;
  const MyApp({super.key, required this.signer});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String current_b64_key='';
  String next_b64_key='';
  String witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC";
  String wit_location =
      '{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://192.168.1.13:3232/"}';
  late Ed25519Signer signer;
  List<String> witness_id_list = [];
  var initiatorKel = '';
  var isIncepting = false;
  var isInceptionError = false;
  List<Identifier> participants = [];
  List<bool> selectedParticipants = [];
  late Identifier identifier;
  String oobiJson = '';
  bool actionClicked = false;
  late Identifier groupIdentifier2;
  late Identifier group_identifier;
  List<Identifier> groupIdentifiers = [];


  @override
  void initState() {
    signer = widget.signer;
    initParameters();
    super.initState();
  }

  Future<void> initParameters() async{
    String dbPath = await getLocalPath();
    dbPath = '$dbPath/new';
    current_b64_key = await signer.getCurrentPubKey();
    next_b64_key = await signer.getNextPubKey();
    await initKel(inputAppDir: dbPath);
  }

  Future<String> getLocalPath() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Multisig demo"),
      ),
      body: SingleChildScrollView(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            RawMaterialButton(
              onPressed: () async{
                List<PublicKey> vec1 = [];
                vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: current_b64_key));
                List<PublicKey> vec2 = [];
                vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: next_b64_key));
                List<String> vec3 = [wit_location];
                setState((){
                  isIncepting = true;
                });
                var icp_event = null;
                try{
                  icp_event = await incept(
                      publicKeys: vec1,
                      nextPubKeys: vec2,
                      witnesses: vec3,
                      witnessThreshold: 1);
                  setState((){
                    isIncepting = false;
                  });
                }catch(e){
                  print(e);
                  setState((){isInceptionError = true;});
                }
                var signature = await signer.sign(icp_event);
                print(icp_event);
                print(signature);
                identifier = await finalizeInception(
                    event: icp_event,
                    signature: await signatureFromHex(
                        st: SignatureType.Ed25519Sha512, signature: signature));

                witness_id_list.add(witness_id);
                var query = await queryMailbox(whoAsk: identifier, aboutWho: identifier, witness: witness_id_list);
                var sig_query = await signer.sign(query[0]);
                await finalizeQuery(identifier: identifier, queryEvent: query[0], signature: await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: sig_query));
                initiatorKel = await getKel(cont: identifier);

                var watcher_oobi = '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://192.168.1.13:3236/"}';
                var add_watcher_message = await addWatcher(controller: identifier, watcherOobi: watcher_oobi);
                print("\nController generate end role message to add witness: $add_watcher_message");
                var watcher_sig = await signer.sign(add_watcher_message);
                var ev = await finalizeEvent(identifier: identifier, event: add_watcher_message, signature: await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: watcher_sig));

                Map<String, String> jsonToOobi = {"cid":identifier.id, "role":"witness", "eid":witness_id};
                Map<String, String> witnessOobi = {"eid":witness_id, "scheme": "http", "url":"http://192.168.1.13:3232/"};
                List<dynamic> toSend = [witnessOobi,jsonToOobi];
                oobiJson = jsonEncode(toSend);

                setState((){});
                final Timer periodicTimer = Timer.periodic(
                  const Duration(seconds: 15),
                      (Timer t) async{
                        List<String> queryEvent = await queryMailbox(whoAsk: identifier, aboutWho: identifier, witness: witness_id_list);
                        var querySignatureList = [];
                        List<ActionRequired> finalizeList = [];
                        for(var event in queryEvent){
                          querySignatureList.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: await signer.sign(event)));
                        }
                        for (int i=0; i<querySignatureList.length; i++){
                          finalizeList = await finalizeQuery(identifier: identifier, queryEvent: queryEvent[i], signature: querySignatureList[i]);
                          if(finalizeList.isNotEmpty){
                            if(!actionClicked){
                              _showMyDialog(finalizeList);
                            }
                          }
                        }

                        for (var group in groupIdentifiers){
                          var groupQuery = await queryMailbox(whoAsk: identifier, aboutWho: group, witness: witness_id_list);
                          var signedGroupQuery = [];
                          for (var singleQuery in groupQuery){
                            signedGroupQuery.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: await signer.sign(singleQuery)));
                          }
                          for (int i=0; i<signedGroupQuery.length; i++) {
                            await finalizeQuery(identifier: identifier,
                                queryEvent: groupQuery[i],
                                signature: signedGroupQuery[i]);
                          }
                        }
                        //print('querying');
                  },
                );
                //print('here');
              },
              child: Padding(
                padding: const EdgeInsets.all(8.0),
                child: const Text("Incept identifier", style: TextStyle(fontWeight: FontWeight.bold),),
              ),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(18.0),
                  side: const BorderSide(width: 2)
              )
            ),
            isIncepting ? connectingToWitness() : Container(),
            isInceptionError ? inceptionError() : Container(),
            initiatorKel.isNotEmpty ? Text("Identifier kel:", style: TextStyle(fontWeight: FontWeight.bold),) : Container(),
            initiatorKel.isNotEmpty ? Text(initiatorKel, style: TextStyle(color: Colors.green),) : Container(),
            initiatorKel.isNotEmpty ? SizedBox(height: 10,) : Container(),
            initiatorKel.isNotEmpty ? Text("Scan this QR code with another device to add this device to their list of participants", style: TextStyle(fontWeight: FontWeight.bold), textAlign: TextAlign.center,) : Container(),
            initiatorKel.isNotEmpty ? QrImage(
              data: oobiJson,
              version: QrVersions.auto,
              size: 200.0,
            ) : Container(),
            initiatorKel.isNotEmpty ? RawMaterialButton(
              onPressed: () async{
                var participantId = await Navigator.push(
                  context,
                  MaterialPageRoute(builder: (context) => const Scanner()),
                );


                var oobiReceived = jsonDecode(participantId);
                print(oobiReceived);
                await sendOobiToWatcher(identifier: identifier, oobisJson: jsonEncode(oobiReceived[0]));
                await sendOobiToWatcher(identifier: identifier, oobisJson: jsonEncode(oobiReceived[1]));


                var participant = await newIdentifier(idStr: oobiReceived[1]['cid']);
                if(!participants.contains(participant)){
                  setState(() {
                    participants.add(participant);
                    selectedParticipants.add(true);
                  });
                }

                List<String> watcherQuery = await queryWatchers(whoAsk: identifier, aboutWho: participant);
                List<Signature> querySignatures = [];
                for(String query in watcherQuery){
                  querySignatures.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: await signer.sign(query)));
                }

                for(int i=0; i<querySignatures.length; i++){
                  await finalizeQuery(identifier: identifier, queryEvent: watcherQuery[i], signature: querySignatures[i]);
                }

                print(watcherQuery);
              },
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: const Text("Scan for participants", style: TextStyle(fontWeight: FontWeight.bold)),
                ),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18.0),
                    side: const BorderSide(width: 2)
                )
            ) : Container(),
            Divider(),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.import_contacts),
                Text("Participants", style: TextStyle(fontWeight: FontWeight.bold),),
                Icon(Icons.import_contacts),
              ],
            ),
            Container(
              width: MediaQuery.of(context).size.width - 100,
              height: 150,
              decoration: BoxDecoration(
                border: Border.all(
                  width: 2.0
              ),
              borderRadius: BorderRadius.all(
                  Radius.circular(18.0)
              ),
              ),
              child: ListView.builder(
                  itemCount: participants.length,
                  itemBuilder: (BuildContext context, int index) {
                    return CheckboxListTile(
                      value: selectedParticipants[index],
                      onChanged: (bool? selected){
                        selectedParticipants[index] = !selectedParticipants[index];
                      },
                      title: Text(participants[index].id),
                    );
                  }),
            ),
            initiatorKel.isNotEmpty ? RawMaterialButton(
                onPressed: () async{
                  var icp = await inceptGroup(
                      identifier: identifier,
                      participants: participants,
                      signatureThreshold: 2,
                      initialWitnesses: witness_id_list,
                      witnessThreshold: 1);
                  var signature = await signer.sign(icp.icpEvent);
                  List<String> signaturesEx = [];
                  List<DataAndSignature> toForward = [];
                  for(var exchange in icp.exchanges){
                    signaturesEx.add(await signer.sign(exchange));
                  }
                  for(int i=0; i<signaturesEx.length; i++){
                    toForward.add(await newDataAndSignature(
                        data: icp.exchanges[i],
                        signature: await signatureFromHex(
                            st: SignatureType.Ed25519Sha512, signature: signaturesEx[i])));
                  }
                  group_identifier = await finalizeGroupIncept(
                      identifier: identifier,
                      groupEvent: icp.icpEvent,
                      signature: await signatureFromHex(
                          st: SignatureType.Ed25519Sha512, signature: signature),
                      toForward: toForward);
                  groupIdentifiers.add(group_identifier);
                },
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: const Text("Incept group", style: TextStyle(fontWeight: FontWeight.bold),),
                ),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18.0),
                    side: const BorderSide(width: 2)
                )
            ) : Container(),
          ],
        ),
      ),
    );
  }

  Widget connectingToWitness(){
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        CircularProgressIndicator(),
        Text("Connecting to witness..."),
      ],
    );
  }

  Widget inceptionError(){
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.not_interested, color: Colors.red,),
        Text("Couldn't connect to witness!", style: TextStyle(color: Colors.red),),
      ],
    );
  }

  Future<void> _showMyDialog(List finalizeList) async {
    return showDialog<void>(
      context: context,
      barrierDismissible: false, // user must tap button!
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('Action Required'),
          content: SingleChildScrollView(
            child: ListBody(
              children: const <Widget>[
                Text('Your mailbox contains a message that requires action'),
                Text('Would you like to continue?'),
              ],
            ),
          ),
          actions: <Widget>[
            TextButton(
              child: const Text('Approve'),
              onPressed: () async{
                setState(() {
                  actionClicked = true;
                });
                for(var entry in finalizeList){
                  if(entry.action == SelectedAction.multisigRequest){
                    var icpSignature = await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: await signer.sign(entry.data));
                    var icpExSignature = await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: await signer.sign(entry.additionaData));
                    groupIdentifier2 = await finalizeGroupIncept(
                        identifier: identifier,
                        groupEvent: entry.data,
                        signature: icpSignature,
                        toForward: [
                          await newDataAndSignature(
                              data: entry.additionaData,
                              signature: icpExSignature)
                        ]
                    );
                    groupIdentifiers.add(groupIdentifier2);
                  }
                }
                Navigator.of(context).pop();
              },
            ),
            TextButton(
              child: const Text('Dismiss'),
              onPressed: () {
                setState(() {
                  actionClicked = false;
                });
                Navigator.of(context).pop();
              },
            ),
          ],
        );
      },
    );
  }

}

