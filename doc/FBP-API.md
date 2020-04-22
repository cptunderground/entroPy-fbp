# FBP API

## Introduce/Detruce Client
### 1:
|Client   	                |ISP_C   	            |ISP_S   	                |Server   	            |   	|
|:-:	                    |:-:	                |:-:	                    |:-:	                |:-:	|
|introduce_me()             |read_introduce()   	|send_introduce()       	|read_introduce()   	|->   	|
|detruce_me()   	        |read_detruce()   	    |send_detruce()         	|read_detruce()   	    |->   	|
|read_result()   	        |send_result()   	    |read_result()   	        |send_result()   	    |<-   	|
|   	                    |   	                |   	                    |   	                |   	|
### 2: 
|Client   	                |ISP_C   	            |ISP_S   	                |Server   	            |   	|
|:-:	                    |:-:	                |:-:	                    |:-:	                |:-:	|
|introduce_me(*bool*)       |read_introduce()   	|send_introduce(*bool*)   	|read_introduce()   	|->   	|
|read_result()   	        |send_result()   	    |read_result()   	        |send_result()   	    |<-   	|
## Announce/Retire Service
### 1:
|Client   	                |ISP_C   	            |ISP_S   	                |Server   	            |   	|
|:-:	                    |:-:	                |:-:	                    |:-:	                |:-:	|
|read_announce()            |send_announce()        |read_announce()       	    |announce_service()   	|<- 	|
|read_retire()   	        |send_retire()   	    |read_retire()           	|retire_service()  	    |<-   	|
### 2:
|Client   	                |ISP_C   	            |ISP_S   	                |Server   	            |   	|
|:-:	                    |:-:	                |:-:	                    |:-:	                |:-:	|
|read_announce()            |send_announce(*bool*)  |read_announce()       	    |announce_service(*bool*)|<- 	|
*does client need to send "ack"?*
## Request Service
|Client   	                |ISP_C   	            |ISP_S   	                |Server   	            |   	|
|:-:	                    |:-:	                |:-:	                    |:-:	                |:-:	|
|send_request(service, ID)  |read_request()       	|send_request(service, ID)	|read_request()        	|->   	|
|read_result()   	        |send_result(ID)   	    |read_result()   	        |send_result(ID)   	    |<-   	|

# Client Pseudo Code
## Send Request
    def send_request(service: str, ID: int, attributes: some class, instance, whatever):
        marshalled_request = marshall(service, ID, attributes)
        wr_feed(marshalled_attributes)
        
        # adapted from rpyc
        conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
        marshalled_response = conn.root.send_request(marshalled_request) #this is the exposed send_request method from the ISP, see rpyc
        result = read_result(marshalled_response)
The send_request method basically just sends serialized information with what the ISP has to do what.
    
    def marshall(service: str, ID: int, attributes: some class, instance, whatever):
Marshalls the given parameters into a serialized datastructure to pass it over the network.
marshalling also provides the code base, so the isp or server get thast aswell
    
    def wr_feed(feed, information):
Should write the ongoing process information on the client to its corresponding feed.
   
## Read Result
    def exposed_send_result(data):
        read_result(data)
    def read_result(response: marshalled_response):
        
        service, ID, result = demarshall(response)
        rd_feed(ID)
        wr_feed(ID, marshalled_response)
        return result
The read_result method just demarshalls the response to the requested service from the ISP. additionally the result gets
written in the feed aswell. The idea behind that is the local storage of already received service results and the 
program can build itself from this feed.
    
    def demarshall(response):
        service = response.extract(service)
        ID = response.extract(ID)
        result = response.extract(result)
        
        return service, ID, response
Demarshalling is the opposite of marshalling. So the response from the ISP gets written back into the instances (or memory). 
    
    def rd_feed(ID):
        load
        
## Introduce/Detruce

On the client side this is just a special typ of send request. The difference will be seen in the ISP, because the ISP does not just forward the request to the dedicated server.

    def introduce_me(status: bool):
        service = "introduce"
        ID = rd_feed(feed=service).nextID()
        attributes = status # True=introduce, False=detruce
        marshalled_request = marshall(service, ID, attributes)
        wr_feed(feed=service,ID=ID, data=marshalled_request)
    
        # adapted from rpyc
        conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
        marshalled_response = conn.root.introduce_me(marshalled_request) #this is the exposed send_introduce method from the ISP, see rpyc
        result = read_result(marshalled_response) #will be a True or False if worked or not
        
    
### OR
    def introduce_me():
        service = "introduce"
        ID = rd_feed(feed=service).nextID()
        attributes = True 
        marshalled_request = marshall(service, ID, attributes)
        wr_feed(feed=service,ID=ID, data=marshalled_request)
    
        # adapted from rpyc
        conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
        marshalled_response = conn.root.introduce_me(marshalled_request) #this is the exposed send_introduce method from the ISP, see rpyc
        result = read_result(marshalled_response) #will be a True or False if worked or not
    
    def detruce_me():
        service = "introduce"
        ID = rd_feed(feed=service).nextID()
        attributes = False
        marshalled_request = marshall(service, ID, attributes)
        wr_feed(feed=service,ID=ID, data=marshalled_request)
    
        # adapted from rpyc
        conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
        marshalled_response = conn.root.detruce_me(marshalled_request) #this is the exposed send_introduce method from the ISP, see rpyc
        result = read_result(marshalled_response) #will be a True or False if worked or not

## Read Announce

Same as in the introduce method, the read_announce is a special case of a read_result. It registers the newly provided service by server.
    
    def exposed_send_announce(marschalled_response):
        read_announce(marschalled_response)
    
    def read_announce(marschalled_response):
        service, ID, result = demarshall(marshalled_response)
        rd_feed(ID)
        wr_feed(ID, marshalled_response)
        if (result.status)
            #announce
            register_service(service, result)
        else:
            #retire
            delete_service(service, result)
        return result
# ISP Pseudo Code
## Read/Send Request
    def exposed_send_request(marshalled_data): #Function client calls
        read_request(marshalled_data):
Exposed functions are the functions the client/server can call after making a connection to the ISP.
Adapted from RPyC Services.
           
    def read_request(marshalled_data):
        service, ID, data = demarshall(marshalled_data)
        
        if(service.is_for_isp()):
            manager = multiprocessing.Manager()
            return_list = manager.list()
            
            process = multiprocessing.Process(target=service, args=(ID, data, return_list)
            process.start()
            process.join()
            
            send_result(service, ID, return_list)
        else:
            send_request(marshalled_data)
            
            
    def send_request(marshalled_data):
        service, ID, data = demarshall(marshalled_data)
        server = server_list.get(service)
        wr_feed(marshalled_attributes)

        # adapted from rpyc
        conn = rpyc.connect(server.ip, server.port, config={"sync_request_timeout": 300})
        marshalled_response = conn.root.send_request(marshalled_request) #this is the exposed send_request method from the ISP, see rpyc
        result = read_result(marshalled_response)
## Read/Send Result
    def exposed_send_result(): #Function server calls
        read_result()
    def read_result(marshalled_data):
        service, ID, data = demarshall(marshalled_data)
        if (service.was_from_isp()):
            rd_feed(ID)
            wr_feed(ID, marshalled_response)
            return result
        else:
            send_result()
    def send_result():
        service, ID, data = demarshall(marshalled_data)
        server = server_list.get(service)
        wr_feed(marshalled_attributes)

        # adapted from rpyc
        conn = rpyc.connect(client.ip, client.port, config={"sync_request_timeout": 300})
        conn.root.send_result(marshalled_request) #this is the exposed send_request method from the client, see rpyc
        
## Read/Send Introduce
    def exposed_introduce_me(data): # Function client calls
        read_introduce(data)
        
    def read_introduce(data):
        introduction_datastruct.register(data.get_user()) -> wr_feed()
        for s in server_list:
            send_introduce(data, s)
            
        
    def send_introduce(data, s):
        server = server_list.get(s)
        
        # adapted from rpyc
        conn = rpyc.connect(server.ip, server.port, config={"sync_request_timeout": 300})
        conn.root.send_introduce(data)
## Read/Send Announce
    def exposed_announce_service(data): #Function the server calls
        read_announce(data)
    
    def read_announce(data):
        if (data.service.is_for_isp()):
            register(data.service) -> wr_feed()
        else:
            for c in introduction_datastruct:
                send_announce(data, c)
    def send_announce():
        client = client_list.get(c)
        
        # adapted from rpyc
        conn = rpyc.connect(client.ip, client.port, config={"sync_request_timeout": 300})
        conn.root.send_announce(data)
# Server Pseudo Code
## Read Request
    def exposed_send_request(marshalled_data): #Function ISP calls
        read_request(marshalled_data)
    def read_request(data):
        result = execute_request(data.service, data.information)
        send_result(service, ID, result)
## Send Result
    def send_result(service, ID, result):
        isp = ID.get_isp()
        package = marshall(service, ID, result)
        conn = rpyc.connect(isp.ip, isp.port, config={"sync_request_timeout": 300})
        conn.root.send_result(data)
        
## Read Introduce
    def exposed_send_introduce(data):
        read_introduce(data)
    def read_introduce(data):
        if (data.bool):
            client_datastruct.register(data.client)
            conn = rpyc.connect(data.isp.ip, data.isp.port, config={"sync_request_timeout": 300})
            conn.root.send_result(*successful*)
            for svc in Services:
                 announce_service(svc)
        else:
            client_datastruct.delete(data.client)
## Announce Service
    def announce_service():
    def retire_service():
    
#Feed
#Data
    class Data():
        self.service
        self.ID
        self.    
*Continued from:*

    //RPC Group
    Server
    announceService()
    retireService()
    readRequest()
    sendResult()

    Client
    introduceMe()
    detruceMe()
    sendRequest()
    readResult() 

    //PubSub Group
    P2P
    createTopic()
    destroyTopic() // ev
    publish(topic, msg)
    subscribe(topic)
    unsubscribe(topic)
    read(topic) -> newest msg, void

    //Capsuling protocol, feeds, general impl. from app
    
    old
    createChannel()
    destroyChannel(Channel)
    post(MSG, Channel)
    inviteToChannel(Channel, User)
    joinChannel(Channel)
    removeFromChannel(User)
    
    Up API - display to User

    Contract Client ISP
    //RPC Group
    ISP
    announceService()
    retireService()
    readRequest()
    sendResult()

    Client
    //introduceMe() -> unused already following
    //detruceMe() -> unused business contract ended
    sendRequest()
    readResult()

    Available ISP services
    C:introduceMe(serviceID, boolean) -> true=introduce, flase=detruce
    S:announce(serviceID, boolean) -> true=announce, flase=retire

    TODO: S:getNextRPC/meetCustomers/collectCustomers(serviceID) -> clientID,boolean* (stream)

    ==> Prototype-Pseudo Code: Client connects to a service via ONE ISP

