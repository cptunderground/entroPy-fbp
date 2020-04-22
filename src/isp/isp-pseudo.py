class ServiceHandlerService(rpyc.Service):  # RPyC implementation
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    def exposed_echo(self, attrs[]

    ):
    proc = pool.Process(target=echo, args=(main_queue, main_event, value, return_list))
    proc.daemon = True
    proc.start()
    proc.join()
    return return_list


def exposed_ping(self, attrs[]

):
...


def exposed_introduce_me(self, attrs[]

):
...


def exposed_detruce_me(self, attrs[]

):
...

class ServiceHandlerService(rpyc.Service):
    def on_connect(self, conn):
        pass


    def on_disconnect(self, conn):
        pass

    def on_exposed_eval_service(self, target, attrs_list):

        proc = pool.Process(target=eval(target), args=(main_queue, main_event, attrs_list, return_list))
        proc.daemon = True
        proc.start()
        proc.join()
        return return_list

def echo(value, return_list):
    try:
        conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
        server = conn.root
        response = server.echo("Echo", value)
        return_list.append(response)
        conn.close()
        return return_list

    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))

if __name__ == '__main__':
    args = get_args(name, server_list) #python isp.py [--name "name"] [--server_list google,ip,port]

    service_handler_server = ThreadedServer(service=ServiceHandlerService, port=18862, ... )
    service_handler_server.start
    name = args.name
    server_list = args.serverlist

    if (args != None):
        for server in server_list:
            server_process = start_process(server.name, server.ip, server.port) #handshake/initial connection
            server_process_list.add(server_process)

    while(alive):
        client_listener = start_listening_process()
        if (client_listener.has_inc_HS):
            client_process = client_listener.fork()
            client_process_list.add(client_process)

