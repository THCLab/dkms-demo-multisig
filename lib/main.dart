import 'dart:async';
import 'dart:convert';
import 'dart:io';

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
  //Keys used to sign the data
  String current_b64_key='';
  String next_b64_key='';

  //Witness data, hardcoded
  String witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC";
  String wit_location =
      '{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://192.168.1.13:3232/"}';
  List<String> witness_id_list = [];

  //Signer instance
  late Ed25519Signer signer;

  //Group initiator id, for UI only
  var initiatorId = '';

  //Inception control flags, for UI only
  var isIncepting = false;
  var isInceptionError = false;

  //Group participants list
  List<Identifier> participants = [];
  List<bool> selectedParticipants = [];

  //Identifier on the device
  late Identifier identifier;

  //QR code string
  String oobiJson = '';

  //Control flag for showing action request alert dialog
  bool actionClicked = false;

  //Group identifiers and its list
  late Identifier groupIdentifier2;
  late Identifier group_identifier;
  List<Identifier> groupIdentifiers = [];

  //UI button flags
  bool isInceptionFinalized = false;
  bool isWatcherAdded = false;
  bool isMailboxQueried = false;

  //Group kel for checking if the usecase works
  String groupKel = '';


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
                //Create keys
                List<PublicKey> vec1 = [];
                vec1.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: current_b64_key));
                List<PublicKey> vec2 = [];
                vec2.add(await newPublicKey(kt: KeyType.Ed25519, keyB64: next_b64_key));
                List<String> vec3 = [wit_location];

                //Start the inception
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

                //Sign and finalize the inception
                var signature = await signer.sign(icp_event);
                print(icp_event);
                print(signature);
                identifier = await finalizeInception(
                    event: icp_event,
                    signature: await signatureFromHex(
                        st: SignatureType.Ed25519Sha512, signature: signature));
                initiatorId = identifier.id;

                //Refresh the UI
                setState((){
                  isInceptionFinalized = true;
                });
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
            initiatorId.isNotEmpty ? Text("Identifier:", style: TextStyle(fontWeight: FontWeight.bold),) : Container(),
            initiatorId.isNotEmpty ? Text(initiatorId, style: TextStyle(color: Colors.green),) : Container(),
            initiatorId.isNotEmpty ? SizedBox(height: 10,) : Container(),
            isInceptionFinalized ? RawMaterialButton(
              onPressed: () async{
                //Add the witness to the list
                witness_id_list.add(witness_id);

                //Query mailbox and finalize it
                var query = await queryMailbox(whoAsk: identifier, aboutWho: identifier, witness: witness_id_list);
                var sig_query = await signer.sign(query[0]);
                await finalizeQuery(identifier: identifier, queryEvent: query[0], signature: await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: sig_query));

                //Refresh the UI
                setState(() {
                  isMailboxQueried = true;
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Mailbox queried!')));
                });
              },
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: const Text("Query mailbox", style: TextStyle(fontWeight: FontWeight.bold),),
                ),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18.0),
                    side: const BorderSide(width: 2)
                )
            ) : Container(),
            isMailboxQueried ? RawMaterialButton(
                onPressed: () async{
                  //Set up the watcher data and add it
                  var watcher_oobi = '{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://192.168.1.13:3236/"}';
                  var add_watcher_message = await addWatcher(controller: identifier, watcherOobi: watcher_oobi);
                  var watcher_sig = await signer.sign(add_watcher_message);
                  var ev = await finalizeEvent(identifier: identifier, event: add_watcher_message, signature: await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: watcher_sig));

                  //Create the QR code to be scanned
                  Map<String, String> jsonToOobi = {"cid":identifier.id, "role":"witness", "eid":witness_id};
                  Map<String, String> witnessOobi = {"eid":witness_id, "scheme": "http", "url":"http://192.168.1.13:3232/"};
                  List<dynamic> toSend = [witnessOobi,jsonToOobi];
                  oobiJson = jsonEncode(toSend);

                  setState((){
                    isWatcherAdded = true;
                  });

                  //Start the query timer
                  final Timer periodicTimer = Timer.periodic(
                    const Duration(seconds: 15),
                        (Timer t) async{
                      //Every 15 seconds query own mailbox
                      List<String> queryEvent = await queryMailbox(whoAsk: identifier, aboutWho: identifier, witness: witness_id_list);
                      var querySignatureList = [];
                      List<ActionRequired> finalizeList = [];

                      //Sign each query
                      for(var event in queryEvent){
                        querySignatureList.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: Platform.isAndroid ? await signer.signNoAuth(event) : await signer.sign(event)));
                      }

                      //Finalize each query
                      for (int i=0; i<querySignatureList.length; i++){
                        finalizeList = await finalizeQuery(identifier: identifier, queryEvent: queryEvent[i], signature: querySignatureList[i]);

                        //If query requires action, show Alert Dialog
                        if(finalizeList.isNotEmpty){
                          if(!actionClicked){
                            _showMyDialog(finalizeList).then((value) => setState((){}));
                          }
                        }
                      }

                      //Every 15 seconds query group mailbox
                      for (var group in groupIdentifiers){
                        var groupQuery = await queryMailbox(whoAsk: identifier, aboutWho: group, witness: witness_id_list);
                        var signedGroupQuery = [];

                        //Sign each query
                        for (var singleQuery in groupQuery){
                          signedGroupQuery.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: Platform.isAndroid ? await signer.signNoAuth(singleQuery) : await signer.sign(singleQuery)));
                        }

                        //Finalize each query
                        for (int i=0; i<signedGroupQuery.length; i++) {
                          await finalizeQuery(identifier: identifier,
                              queryEvent: groupQuery[i],
                              signature: signedGroupQuery[i]);
                        }
                      }
                    },
                  );
                },
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: const Text("Add watcher", style: TextStyle(fontWeight: FontWeight.bold),),
                ),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18.0),
                    side: const BorderSide(width: 2)
                )
            ) : Container(),
            isWatcherAdded ? Text("Scan this QR code with another device to add this device to their list of participants", style: TextStyle(fontWeight: FontWeight.bold), textAlign: TextAlign.center,) : Container(),
            isWatcherAdded ? QrImage(
              data: oobiJson,
              version: QrVersions.auto,
              size: 200.0,
            ) : Container(),
            isWatcherAdded ? RawMaterialButton(
              onPressed: () async{
                //Get the group participant json from QR
                var participantId = await Navigator.push(
                  context,
                  MaterialPageRoute(builder: (context) => const Scanner()),
                );

                //Decode the QR and send the oobi to watcher
                var oobiReceived = jsonDecode(participantId);
                print(oobiReceived);
                await sendOobiToWatcher(identifier: identifier, oobisJson: jsonEncode(oobiReceived[0]));
                await sendOobiToWatcher(identifier: identifier, oobisJson: jsonEncode(oobiReceived[1]));

                //Add the participant from the QR to the list of participants, refresh the list
                var participant = await newIdentifier(idStr: oobiReceived[1]['cid']);
                if(!participants.contains(participant)){
                  setState(() {
                    participants.add(participant);
                    selectedParticipants.add(true);
                  });
                }

                //Query the watcher about new participant
                List<String> watcherQuery = await queryWatchers(whoAsk: identifier, aboutWho: participant);
                List<Signature> querySignatures = [];

                //Sign the query
                for(String query in watcherQuery){
                  querySignatures.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: await signer.sign(query)));
                }

                //Finalize the query
                for(int i=0; i<querySignatures.length; i++){
                  await finalizeQuery(identifier: identifier, queryEvent: watcherQuery[i], signature: querySignatures[i]);
                }
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
            isWatcherAdded ? RawMaterialButton(
                onPressed: () async{
                  //Create group inception event
                  var icp = await inceptGroup(
                      identifier: identifier,
                      participants: participants,
                      signatureThreshold: 2,
                      initialWitnesses: witness_id_list,
                      witnessThreshold: 1);

                  //Sign the event and the exchanges
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

                  //Get the group_identifier by finalizing group incept
                  group_identifier = await finalizeGroupIncept(
                      identifier: identifier,
                      groupEvent: icp.icpEvent,
                      signature: await signatureFromHex(
                          st: SignatureType.Ed25519Sha512, signature: signature),
                      toForward: toForward);
                  groupIdentifiers.add(group_identifier);
                  setState(() {});
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
            Divider(),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.group),
                Text("Groups", style: TextStyle(fontWeight: FontWeight.bold),),
                Icon(Icons.group),
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
                  itemCount: groupIdentifiers.length,
                  itemBuilder: (BuildContext context, int index) {
                    return Text(groupIdentifiers[index].id);
                  }),
            ),
            groupIdentifiers.isNotEmpty ?
            RawMaterialButton(
              onPressed: () async{
                groupKel = await getKel(cont: groupIdentifiers[0]);
                setState(() {

                });

                if(group_identifier != null){
                  for (var group in groupIdentifiers){
                    var groupQuery = await queryMailbox(whoAsk: identifier, aboutWho: group, witness: witness_id_list);
                    var signedGroupQuery = [];

                    //Sign each query
                    for (var singleQuery in groupQuery){
                      signedGroupQuery.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: Platform.isAndroid ? await signer.signNoAuth(singleQuery) : await signer.sign(singleQuery)));
                    }

                    //Finalize each query
                    for (int i=0; i<signedGroupQuery.length; i++) {
                      await finalizeQuery(identifier: identifier,
                          queryEvent: groupQuery[i],
                          signature: signedGroupQuery[i]);
                    }
                  }

                  for (var group in groupIdentifiers){
                    var groupQuery = await queryMailbox(whoAsk: identifier, aboutWho: group, witness: witness_id_list);
                    var signedGroupQuery = [];

                    //Sign each query
                    for (var singleQuery in groupQuery){
                      signedGroupQuery.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: Platform.isAndroid ? await signer.signNoAuth(singleQuery) : await signer.sign(singleQuery)));
                    }

                    //Finalize each query
                    for (int i=0; i<signedGroupQuery.length; i++) {
                      await finalizeQuery(identifier: identifier,
                          queryEvent: groupQuery[i],
                          signature: signedGroupQuery[i]);
                    }
                  }
                }else{
                  for (var group in groupIdentifiers){
                    var groupQuery = await queryMailbox(whoAsk: identifier, aboutWho: group, witness: witness_id_list);
                    var signedGroupQuery = [];

                    //Sign each query
                    for (var singleQuery in groupQuery){
                      signedGroupQuery.add(await signatureFromHex(st: SignatureType.Ed25519Sha512, signature: Platform.isAndroid ? await signer.signNoAuth(singleQuery) : await signer.sign(singleQuery)));
                    }

                    //Finalize each query
                    for (int i=0; i<signedGroupQuery.length; i++) {
                      await finalizeQuery(identifier: identifier,
                          queryEvent: groupQuery[i],
                          signature: signedGroupQuery[i]);
                    }
                  }
                }
              },
              child: Padding(
                padding: const EdgeInsets.all(8.0),
                child: const Text("query(temp)", style: TextStyle(fontWeight: FontWeight.bold)),
              ),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(18.0),
                  side: const BorderSide(width: 2)
              )
            ) : Container(),
            RawMaterialButton(
                onPressed: () async{
                  groupKel = await getKel(cont: groupIdentifiers[0]);
                  setState(() {

                  });
                },
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: const Text("Get group kel", style: TextStyle(fontWeight: FontWeight.bold)),
                ),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18.0),
                    side: const BorderSide(width: 2)
                )
            ),
            groupKel.isNotEmpty ? Text("Group kel:", style: TextStyle(fontWeight: FontWeight.bold),) : Container(),
            groupKel.isNotEmpty ? Text(groupKel, style: TextStyle(color: Colors.green),) : Container(),
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
                  print(entry.action);
                  var selectedAction = SelectedAction.multisigRequest;
                  if(entry.action == selectedAction.action){
                    print('wlazło');
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
                    print(groupIdentifier2);
                    groupIdentifiers.add(groupIdentifier2);
                    setState(() {});
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

