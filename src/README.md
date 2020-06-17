# Feed Bundling Protocol Prototype Version 0.4
This implementation orientates itself on the Feed Bundling Protocol version 0.4 developped by Prof. Christian Tschudin and Jannik Jaberg. 

Picture and description


# Running Client, ISP and Server

Installing all packages:

    pip3 install [package]

    packages: 

Until today the implementation supports one predefined client, ISP and server for the given situation. All configurations are stored in the corresponding config files. To start each node invoke as followed
    
    python3 nisp.py isp001-config.json
    
For now it is important to run the ISP code first, since it generates also the folders for "all" clients and servers. Afterwards start client and server as followed:

    python3 nclient.py fff111-config.json
    python3 nserver.py ser001-config.json
    
If all consoles show the text "Node is setup" you are ready to go!

# Using FBP

The client console should print out the following: INFO:root:next input:, now you can request services from the ISP or server with:

    --service -destination [attributes]
or
    
    service=service destination=destination attributes=[attributes]

Let me give you an example: 

    --echo -isp001 ['an echo']
    service=echo destination=isp001 attributes=['an echo']

Working services should be: echo and add






Either you choose an existing name from the feeds/ folder or create your own client

    python3 isp.py name peers
    
For the ISP it functions the same but one peer has to be specified since the ISP communicates with several clients

-> More than one connection will be implemented