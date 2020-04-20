

if __name__ == '__main__':
    args = get_args(name, server_list) #python isp.py [--name "name"] [--server_list google,ip,port]

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

