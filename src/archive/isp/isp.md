# ISP Pseudo Code
The isp is the most complex part of the whole system, it merges client and server functionalities into one.
In the first place the ISP has to listen to the clients service requests and handle and convert them into real service requests
for the corresponding server.

    if __name__ == '__main__':
        service_handler_server = ThreadedServer(service=ServiceHandlerService, port=18862, ... ) #Syntax from RPyC
        service_handler_server.start
        
Inside the ServiceHandlerService all the request of the client get registered and distributed to the servers. 
Following are the exposed services if the client has a 1 to 1 implementation of all available services:

    class ServiceHandlerService(rpyc.Service): #RPyC implementation
        def on_connect(self, conn):
            pass
    
        def on_disconnect(self, conn):
            pass
    
        def exposed_echo(self, attrs[]):
            manager = multiprocessing.Manager()
            return_list = manager.list()
            proc = multiprocessing.Process(target=echo, args=(main_queue, main_event, value, return_list))
            proc.daemon = True
            proc.start()
            proc.join()
            return return_list
    
        def exposed_ping(self, attrs[]):
            ...
    
        def exposed_introduce_me(self, attrs[]):
            ...
    
        def exposed_detruce_me(self, attrs[]):
            ...

As I mentioned in the cliend.md it would be much better if most of the functionality is not implemented in the client,
 rather the client sends strings and the isp evaluates them
 
    class ServiceHandlerService(rpyc.Service):
        def on_connect(self, conn):
            pass
    
        def on_disconnect(self, conn):
            pass
    
        def on_exposed_eval_service(self, target, attrs[]):
            manager = multiprocessing.Manager()
            return_list = manager.list()
            proc = multiprocessing.Process(target=eval(target), args=(main_queue, main_event, value, return_list))
            proc.daemon = True
            proc.start()
            proc.join()
            return return_list

Both handlers pass everything to the target methods, here is one target method:
            
    def echo(value, return_list):
    try:
        conn = rpyc.connect("google", 12345, config={"sync_request_timeout": 300})
        server = conn.root
        response = server.echo(value)
        return_list.append(response)
        conn.close()
        return return_list

    except Exception: #from RPyC
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))