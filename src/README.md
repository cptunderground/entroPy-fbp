# Feed Bundling Protocol Prototype Version 0.4
This implementation orientates itself on the Feed Bundling Protocol version 0.4 developped by Prof. Christian Tschudin and Jannik Jaberg. 

Picture and description


# Running Client, ISP and Server

Installing all packages:

    pip3 install [package]

    packages: 
    - cbor2
    - pynacl
    - watchdog

Until today the implementation supports one predefined client, ISP and server for the given situation. All configurations are stored in the corresponding config files. 
Make sure the feeds folder is **empty**! To start each node invoke as followed
    
    python3 nisp.py contracts/isp001-config.json
    
For now it is important to run the ISP code first, since it generates also the folders for "all" clients and servers. Afterwards start client and server as followed:

    python3 nclient.py contracts/cli001-config.json
    python3 nserver.py contracts/ser001-config.json
    
If all consoles show the text "Node is setup" you are ready to go!

# Using FBP
## RPC Request to ISP
The client console should print out the following: INFO:root:next input:, now you can request services from the ISP or server with:

    --service -destination [attributes]
or
    
    service=service destination=destination attributes=[attributes]

Let me give you an example: 

    --echo -isp001 ['an echo']
    service=echo destination=isp001 attributes=['an echo']

To see, what services are available at the ISP invoke the getcatalog service as followed:

    --servicecatalog -isp001 [None]
    service=servicecatalog destination=isp001 attributes=[None]

And the client console will print out something like this:

    06/17/2020 02:03:41 PM result -> [
        ['668053..0d064b', 2, '1f4dd2..c29008', 0, [0, 'e8977e..661385']],
        'c1e475..eff606',
        {'ID': 0, 'type': 'result', 'service': 'servicecatalog', 'result': 'Service catalog: 
            [
                 (\'add\', \'The add service takes a list of integers and adds them together\\n:param attributes: A list of integers\\n:return: the sum of all integers in the list\'),
                 (\'echo\', \':param attributes: Any\\n:return: The given attributes as is\'), 
                 (\'getservers\', ":param: \'All\'\\n:return: every registered server key"), 
                 (\'invalid_attributes\', \'If a service is invoked with poorly chosen attributes, it passes these here and an error message gets returned.\\n:param attributes: Any\\n:return: Error\'), 
                 (\'testservice\', \'This service is just a testing service. It returns 0 on any given param.\\n:param attributes: Any\\n:return: 0\')
            ]'
         }
    ]

If no line with *result ->* shows, just refresh the console by typing:
    
    refresh

into it.

## Introducing to a Server
Since the idea of the FBP is to bundle feeds from arbitrary many clients to a server, the connection to a server has to be established.
In my implementation the client *introduces* itself to the server and makes it the offer to accept request from the client.
Afterwards, if either client or server are not interested in each other anymore they detruce themselfes, but later on more.

So to introduce a client to a server procede as followed:

    --introduce -isp001 ['ser001']
    service=introduce destination=isp001 attributes=['ser001']

*In the server console you can now either accept or decline the introducing client. Due to still unsolved multithreading issues,
the first accept will cause the server to refuse the input and it will say, that the input does not match the given regex pattern. 
Just type accept once more and the server will accept the client. This is also the case for declining a client.* - this was 
originally a feature, but caused too much problems with the multi client, multi server approach and is not implemented at the point.

A server will automatically accept each client it gets introduced, and responds with an approval.

After that refresh the client as described above and the client will print something like this:

    06/17/2020 02:26:20 PM -> [['89cb08..5a964a', 2, '656ca9..ac492b', 0, [0, 'b3c44a..bdd091']], '985b9e..62f505', {'ID': 0, 'type': 'result', 'source': 'isp001', 'destination': 'does not matter', 'service': 'introduce', 'result': 'ser001'}]
    06/17/2020 02:26:20 PM # new ED25519 key pair: ALWAYS keep the private key as a secret
    06/17/2020 02:26:20 PM {
      'type': 'ed25519',
      'public': '97e63b0888c58e068a2add263f0b5d8430ebae8ba03408e41e9a2889d170b636',
      'private': 'a3650c73badae881cbf5d4cd2dde5ce7e14060b4a7797593ba0d0f2857934006'
    }

Congratulations, your client have introduced itself successfully to the server.

If you declined the client, the output will be:

    06/17/2020 02:31:55 PM -> [['3ff9a0..ca57a2', 2, '958b56..dcb53f', 0, [0, 'a77b53..0ec858']], '1ad705..72b806', {'ID': 0, 'type': 'result', 'source': 'isp001', 'destination': 'does not matter', 'service': 'introduce', 'result': 'declined'}]

From there the introduce request is completed, also successfully but your client is not introduced to the server. 
Now you just can reintroduce your client and accept it on the server to procede with the FBP demonstartion.

## RPC Request to Server

The established connection to the server now enables to request services from the server. This functions the same way as requesting a Service on
 the ISP, but the destination now is the key of the introduced server:
 
    --echo -ser001 ['Another echo']
    service=echo destination=ser001 attributes=['Another echo']
    
The resulting output on the client after a refresh:

    06/17/2020 02:39:34 PM result -> [
        ['d34efb..5fc314', 3, '7c4c7b..0c6e8a', 0, [0, '5f42b4..704c03']],
        '089304..bd0100', 
        {'ID': 3, 'type': 'result', 'source': 'ser001', 'destination': 'cli001', 'service': 'echo', 'attributes': 'Another echo', 'result': 'got it'}
    ]
    
As you can see the result is just a 'got it' string. This is because the server does not yet support services as the ISP. 

## Detrucing Client from Server - Client Side
If after some time a client maybe loses the interest in the services of a server. The it can detruce itself from the server.
 Detrucing causes the server to forget all the information from the client as well as deleting the communication feeds on both sides, server and client. 
 To detruce proceed as followed:
    
    --detruce -isp001 ['ser001']
    service=detruce destination=isp001 attributes=['ser001']

Output:

    06/17/2020 02:50:30 PM -> [['84c62d..f3a6f6', 3, '6999ba..4b68e3', 0, [0, '98ab14..d912bf']], 'bfec6d..504803', {'ID': 2, 'type': 'result', 'source': 'isp001', 'destination': 'does not matter', 'service': 'detruce', 'result': 'approved'}]
    06/17/2020 02:50:30 PM Successfully detruced from server  
    
Now the client can reintroduce itself to the server, if it wants to communicate again.

## Detrucing Server from Client - Server Side
Perhaps also a server does no longer want to answer request of a specific client. Therefore also a server can detruce from a client. 
For this type as followed in the server console:

    --detruce -cli001
    
cli001 is the key of the client. 
Now either read the server request in the client console by typing *read* into it or try to send a new request, the client will
 detect the detruce and inform:
 
    06/17/2020 03:16:26 PM Server:ser001 detruced from you! You can no longer communicate with it. Try introducing!

## Disclaimer
If the implementation is not exactly used as described above, it can result in a dead end or crash. This is a prototype
implementation to explore the mechanics of a Feed Bundle Protocol. Theoretically this implementation supports multi client and
server support (cli001 till cli005 and ser001 and ser002). Practically still some major errors may occur if used wrongly.
To use the multi node approach, just open new terminals and start as described by 
changing cli001 to cli002 untill cli005 and ser001 by ser002. Every client can introduce to every server.
 