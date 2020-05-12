import argparse
import hashlib
import json

import os

import cbor2

import lib.feed as feed
import lib.pcap as pcap
import lib.crypto as crypto
import services

import logging


class Server():
    def __init__(self, name: str, server_isp_feed: str, isp_server_feed: str, isp_server_key: str,
                 highest_introduce_ID: int,
                 open_introduces: list):
        self.name = name
        self.server_isp_feed = server_isp_feed
        self.isp_server_feed = isp_server_feed
        self.isp_server_key = isp_server_key
        self.highest_introduce_ID = highest_introduce_ID
        self.open_introduces = open_introduces

    def to_string(self):
        return f'{self.name}, {self.server_isp_feed}, {self.isp_server_feed}, {self.isp_server_key}, {self.highest_introduce_ID}, {self.open_introduces}'

    def encode(self):
        return self.__dict__


class Client():
    def __init__(self, name: str, client_isp_feed: str, isp_client_feed: str, isp_client_key: str,
                 highest_request_ID: int,
                 open_requests: list):
        self.name = name
        self.client_isp_feed = client_isp_feed
        self.isp_client_feed = isp_client_feed
        self.isp_client_key = isp_client_key
        self.highest_request_ID = highest_request_ID
        self.open_requests = open_requests

    def to_string(self):
        return f'{self.name}, {self.client_isp_feed}, {self.isp_client_feed}, {self.isp_client_key}, {self.highest_request_ID}, {self.open_requests}'

    def encode(self):
        return self.__dict__


def init():
    global client_names
    global client_dict

    global server_names
    global server_dict

    name = args.name

    # Create isp_client feeds
    for client in client_names:
        if os.path.exists(f'feeds/{name}/{name}_{client}.pcap') and os.path.exists(f'feeds/{name}/{name}_{client}.key'):
            logging.info(f'Feed and key for {name} exist')
            # isp to client feeds
            isp_client_key = f'feeds/{name}/{name}_{client}.key'
            isp_client_feed = f'feeds/{name}/{name}_{client}.pcap'

            client_class = Client(client, 'unknown', isp_client_feed, isp_client_key, 0, [])
            client_dict[client] = client_class
            logging.info(f'ISP-FEED:{isp_client_feed}')
            logging.info(f'ISP-KEY:{isp_client_key}')

        else:
            logging.info(f'Feed for {name} does not exist')
            logging.info(f'Creating feed for {name}')
            key_pair = crypto.ED25519()
            key_pair.create()
            header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
            keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            logging.warning("# new ED25519 key pair: ALWAYS keep the private key as a secret")
            logging.warning('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            if not os.path.exists(f'feeds/{name}'):
                os.mkdir(f'feeds/{name}')
            f = open(f'feeds/{name}/{name}_{client}.key', 'w')
            f.write(header)
            f.write(keys)
            f.close()

            try:
                os.remove(f'feeds/{name}/{name}_{client}.pcap')
            except:
                pass

            isp_client_key = f'feeds/{name}/{name}_{client}.key'
            isp_client_feed = f'feeds/{name}/{name}_{client}.pcap'

            client_class = Client(client, 'unknown', isp_client_feed, isp_client_key, 0, [])
            client_dict[client] = client_class

            logging.info(f'Created Feed for {name} in {isp_client_feed}')
            logging.info(f'Created Key for {name} in {isp_client_key}')

            # TODO exchange source and dest with public keys
            feed_entry = {
                'ID': 0,
                'type': 'initiation',
                'source': name,
                'destination': name,
                'service': 'init',
                'attributes': None
            }

            logging.info(f'Writing in {isp_client_feed}: {feed_entry}')
            fid, signer = feed.load_keyfile(isp_client_key)
            feed.FEED(isp_client_feed, fid, signer, True).write(feed_entry)

            # services.announce_all_services(client_class)

    for server in server_names:
        if os.path.exists(f'feeds/{name}/{name}_{server}.pcap') and os.path.exists(
                f'feeds/{name}/{name}_{server}.key'):
            logging.info(f'Feed and key for {name} exist')
            # isp to client feeds
            isp_server_key = f'feeds/{name}/{name}_{server}.key'
            isp_server_feed = f'feeds/{name}/{name}_{server}.pcap'

            server_class = Server(server, 'unknown', isp_server_feed, isp_server_key, 0, [])
            server_dict[server] = server_class
            logging.info(f'ISP-FEED:{isp_server_feed}')
            logging.info(f'ISP-KEY:{isp_server_key}')

        else:
            logging.info(f'Feed for {name} does not exist')
            logging.info(f'Creating feed for {name}')
            key_pair = crypto.ED25519()
            key_pair.create()
            header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
            keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            logging.warning("# new ED25519 key pair: ALWAYS keep the private key as a secret")
            logging.warning('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            if not os.path.exists(f'feeds/{name}'):
                os.mkdir(f'feeds/{name}')
            f = open(f'feeds/{name}/{name}_{server}.key', 'w')
            f.write(header)
            f.write(keys)
            f.close()

            try:
                os.remove(f'feeds/{name}/{name}_{server}.pcap')
            except:
                pass

            isp_server_key = f'feeds/{name}/{name}_{server}.key'
            isp_server_feed = f'feeds/{name}/{name}_{server}.pcap'

            server_class = Server(server, 'unknown', isp_server_feed, isp_server_key, 0, [])
            server_dict[server] = server_class

            logging.info(f'Created Feed for {name} in {isp_server_feed}')
            logging.info(f'Created Key for {name} in {isp_server_key}')

            # TODO exchange source and dest with public keys
            feed_entry = {
                'ID': 0,
                'type': 'initiation',
                'source': name,
                'destination': name,
                'service': 'init',
                'attributes': None
            }

            logging.info(f'Writing in {isp_server_feed}: {feed_entry}')
            fid, signer = feed.load_keyfile(isp_server_key)
            feed.FEED(isp_server_feed, fid, signer, True).write(feed_entry)
    #


def init_clients():
    global client_dict
    global client_names

    isp_name = args.name

    for name in client_names:
        if os.path.exists(f'feeds/{name}/{name}_{isp_name}.pcap'):

            client_log = f'feeds/{name}/{name}_{isp_name}.pcap'

            logging.info(f'Feed for {name} exists')
            logging.info(f'Client-LOG:{client_log}')

            client = client_dict[name]
            client.client_isp_feed = client_log
            print(client_dict[name].to_string())

            p = pcap.PCAP(client_log)
            p.open('r')
            for w in p:
                # here we apply our knowledge about the event/pkt's internal struct
                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])
                # rewrite the packet's byte arrays for pretty printing:
                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                print('here')
                if isinstance(e[2], dict) and e[2]['type'] == 'request':
                    request_ID = e[2]["ID"]
                    logging.debug(f'ID={e[2]["ID"]}')
                    logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                    logging.debug(f"   hashref={href.hex()}")
                    logging.debug(f"   content={e[2]}")

                    client.open_requests.append(request_ID)
                    client.highest_request_ID = max(request_ID, client.highest_request_ID)

            p.close()

            client = client_dict[name]

            p = pcap.PCAP(client.isp_client_feed)
            p.open('r')
            for w in p:
                # here we apply our knowledge about the event/pkt's internal struct
                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])
                # rewrite the packet's byte arrays for pretty printing:
                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                print('here')
                if isinstance(e[2], dict) and e[2]['type'] == 'result':
                    request_ID = e[2]["ID"]
                    logging.debug(f'ID={e[2]["ID"]}')
                    logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                    logging.debug(f"   hashref={href.hex()}")
                    logging.debug(f"   content={e[2]}")

                    if client.open_requests.__contains__(e[2]['ID']):
                        client.open_requests.remove(e[2]['ID'])
                        # read_request(e[2])
                    else:
                        pass

            p.close()

            p = pcap.PCAP(client_log)
            p.open('r')
            for w in p:
                # here we apply our knowledge about the event/pkt's internal struct
                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])
                # rewrite the packet's byte arrays for pretty printing:
                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                print('here')
                if isinstance(e[2], dict) and e[2]['type'] == 'request':
                    request_ID = e[2]["ID"]
                    logging.debug(f'ID={e[2]["ID"]}')
                    logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                    logging.debug(f"   hashref={href.hex()}")
                    logging.debug(f"   content={e[2]}")

                    print(f'req id {request_ID}')
                    if client.open_requests.__contains__(request_ID):
                        read_request(e[2], client)

            p.close()



        else:
            logging.critical(f'Feed for {name} does not exist')

            pass


def init_servers():
    global server_dict
    global server_names

    isp_name = args.name

    for name in server_names:
        if os.path.exists(f'feeds/{name}/{name}_{isp_name}.pcap'):

            server_log = f'feeds/{name}/{name}_{isp_name}.pcap'

            logging.info(f'Feed for {name} exists')
            logging.info(f'server-LOG:{server_log}')

            server = server_dict[name]
            server.server_isp_feed = server_log
            print(server_dict[name].to_string())

            p = pcap.PCAP(server.isp_server_feed)
            p.open('r')
            for w in p:
                # here we apply our knowledge about the event/pkt's internal struct
                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])
                # rewrite the packet's byte arrays for pretty printing:
                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                if isinstance(e[2], dict) and e[2]['type'] == 'introduce':
                    introduce_ID = e[2]["introduce_ID"]

                    logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                    logging.debug(f"   hashref={href.hex()}")
                    logging.debug(f"   content={e[2]}")

                    server.open_introduces.append(introduce_ID)
                    server.highest_introduce_ID = max(introduce_ID, server.highest_introduce_ID)

            p.close()

            p = pcap.PCAP(server.server_isp_feed)
            p.open('r')
            for w in p:
                # here we apply our knowledge about the event/pkt's internal struct
                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])
                # rewrite the packet's byte arrays for pretty printing:
                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                print('here')
                if isinstance(e[2], dict) and e[2]['type'] == 'approved_introduce':
                    introduce_ID = e[2]["introduce_ID"]
                    logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                    logging.debug(f"   hashref={href.hex()}")
                    logging.debug(f"   content={e[2]}")

                    if server.open_introduces.__contains__(introduce_ID):
                        server.open_introduces.remove(introduce_ID)
                        # read_request(e[2])
                    else:
                        pass

            p.close()





        else:
            logging.critical(f'Feed for {name} does not exist')

            pass


def send_result(log_entry, result, client: Client):
    global next_result_ID
    feed_entry = {
        'ID': log_entry['ID'],
        'type': 'result',
        'source': args.name,
        'destination': log_entry['source'],
        'service': log_entry['service'],
        'result': result
    }

    logging.info(f'Sending result')
    logging.info(f'Writing in {client.isp_client_feed}: {feed_entry}')
    client.highest_request_ID += 1
    wr_feed(client.isp_client_feed, client.isp_client_key, feed_entry)


def send_request(request: dict):
    global next_request_ID
    global server_log

    # TODO exchange sourece and dest with public keys
    feed_entry = {
        'ID': next_request_ID,
        'type': 'request',
        'source': args.name,
        'destination': request['destination'],
        'service': request['service'],
        'attributes': request['attributes']
    }
    next_request_ID += 1

    print(f'writing in {isp_log}: {feed_entry}')
    wr_feed(isp_log, isp_key, feed_entry)
    await_result(feed_entry['ID'])


def await_result(ID):
    global result_ID_list
    result_ID_list.append(ID)


def clear_await(ID):
    global result_ID_list
    result_ID_list.remove(ID)


def wr_feed(f, key, msg):
    feed.append_feed(f, key, msg)


def send_invalid_result(log_entry, error, client: Client):
    send_result(log_entry, f'Invalid request - source:{error}', client)


def invalid_format(log_entry, client: Client):
    logging.warning("INVALID LOG ENTRY")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'format', client)


def invalid_service(log_entry, client: Client):
    logging.warning("INVALID SERVICE")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'service', client)


def invalid_destination(log_entry, client: Client):
    logging.warning("INVALID DESTINATION")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'destination', client)


def read_request(log_entry: dict, client: Client):
    logging.info(log_entry['ID'])
    if log_entry['ID'] == None:
        invalid_format(log_entry, client)
    elif log_entry['type'] == None:
        invalid_format(log_entry, client)
    elif log_entry['source'] == None:
        invalid_format(log_entry, client)
    elif log_entry['destination'] == None:
        invalid_format(log_entry, client)
    elif log_entry['service'] == None:
        invalid_format(log_entry, client)
    else:
        handle_request(log_entry, client)


def read_introduce(log_entry, client: Client):
    server = server_dict[log_entry['attributes']]

    if log_entry['ID'] > client.highest_request_ID:

        introduce_entry = {
            'introduce_ID': server.highest_introduce_ID,
            'request_ID': log_entry['ID'],
            'request_source': client.name,
            'debug' : log_entry['destination'],
            'type': 'introduce',
            'attributes': client.name
        }

        # send introduce
        wr_feed(server.isp_server_feed, server.isp_server_key, introduce_entry)
        server.open_introduces.append(server.highest_introduce_ID)
        server.highest_introduce_ID += 1
        client.highest_request_ID += 1
    else:
        print('ALREADY HANDLED')

def handle_approved_introduce(server: Server):
    global client_dict

    p = pcap.PCAP(server.server_isp_feed)
    p.open('r')
    for w in p:
        # here we apply our knowledge about the event/pkt's internal struct
        e = cbor2.loads(w)
        href = hashlib.sha256(e[0]).digest()
        e[0] = cbor2.loads(e[0])
        # rewrite the packet's byte arrays for pretty printing:
        e[0] = pcap.base64ify(e[0])
        fid = e[0][0]
        seq = e[0][1]
        if e[2] != None:
            e[2] = cbor2.loads(e[2])

        if isinstance(e[2], dict) and e[2]['type'] == 'approved_introduce' and server.open_introduces.__contains__(e[2]['introduce_ID']):
            logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            logging.debug(f"   hashref={href.hex()}")
            logging.debug(f"   content={e[2]}")

            client = client_dict[e[2]['request_source']]

            result = e[2]['result']

            feed_entry = {
                'ID': e[2]['request_ID'],
                'type': 'result',
                'source': args.name,
                'destination': 'does not matter',
                'service': 'introduce',
                'result': result,
                'debug' : e[2]['debug']
            }

            logging.info(f'Sending INTRODUCTION result')
            logging.info(f'Writing in {client.isp_client_feed}: {feed_entry}')
            server.open_introduces.remove(e[2]['introduce_ID'])
            wr_feed(client.isp_client_feed, client.isp_client_key, feed_entry)

    p.close()


def handle_request(log_entry, client: Client):
    # TODO dynamic switching over destination
    print(log_entry)
    if log_entry['service'] == 'introduce':
        print('INTRODUCE')
        read_introduce(log_entry, client)

    elif log_entry['service'] == 'servicecatalog':

        try:
            logging.info(f'Evaluating service')
            f = eval(f'services.{log_entry["service"]}')
            result = f(log_entry['attributes'])
            send_result(log_entry, result, client)
        except:
            invalid_service(log_entry, client)

    else:
        try:
            logging.info(f'Evaluating service')
            f = eval(f'services.Service.{log_entry["service"]}')
            result = f(log_entry['attributes'])
            send_result(log_entry, result, client)
        except:
            invalid_service(log_entry, client)


def on_created(event):
    # TODO init on RT
    logging.info(f"hey, {event.src_path} has been created!")


def on_deleted(event):
    logging.critical(f"what the f**k! Someone deleted {event.src_path}!")


def on_modified(event):
    # TODO Regex to check if it is feed file and then handle over feed file
    logging.info(f"Feed update:{event.src_path}")

    global client_dict

    if 'client' in f'{event.src_path}':

        for client in client_dict.values():

            if f'{event.src_path[2:]}' == client.client_isp_feed:
                logging.info(f'Handling client incoming')
                handle_new_requests(client)

    if 'server' in f'{event.src_path}':

        for server in server_dict.values():
            print(server.to_string())
            if f'{event.src_path[2:]}' == server.server_isp_feed:
                logging.info(f'SERVERINC')
                handle_approved_introduce(server)


def on_moved(event):
    logging.critical(f"ok ok ok, someone moved {event.src_path} to {event.dest_path}")


def handle_new_requests(client: Client):
    p = pcap.PCAP(client.client_isp_feed)
    p.open('r')
    for w in p:
        # here we apply our knowledge about the event/pkt's internal struct
        e = cbor2.loads(w)
        href = hashlib.sha256(e[0]).digest()
        e[0] = cbor2.loads(e[0])
        # rewrite the packet's byte arrays for pretty printing:
        e[0] = pcap.base64ify(e[0])
        fid = e[0][0]
        seq = e[0][1]
        if e[2] != None:
            e[2] = cbor2.loads(e[2])

        if isinstance(e[2], dict) and e[2]['type'] == 'request':
            request_ID = e[2]["ID"]
            logging.debug(f'ID={e[2]["ID"]}')
            logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            logging.debug(f"   hashref={href.hex()}")
            logging.debug(f"   content={e[2]}")

            # TODO handle IDs
            logging.info(f'request ID {request_ID}  next res {next_result_ID}')
            if request_ID > client.highest_request_ID:
                read_request(e[2], client)
            elif client.open_requests.__contains__(request_ID):
                client.open_requests.remove(request_ID)
                read_request(e[2], client)

    p.close()


def start_watchdog():
    import time
    from watchdog.observers import Observer
    from watchdog.events import PatternMatchingEventHandler
    patterns = "*"
    ignore_patterns = ""
    ignore_directories = True
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)

    my_event_handler.on_created = on_created
    my_event_handler.on_deleted = on_deleted
    my_event_handler.on_modified = on_modified
    my_event_handler.on_moved = on_moved

    path = "./feeds"
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    my_observer.start()
    logging.debug(f'Starting observing feeds')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-ISP for FBP')
    # parser.add_argument('--keyfile')
    # parser.add_argument('pcapfile', metavar='PCAPFILE')
    parser.add_argument('name')
    parser.add_argument('peers')  # TODO LIST
    # parser.add_argument('--debug')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    client_names = ['client']  # 01', 'client02', 'client03', 'client04']
    server_names = ['server']  # 01', 'server02', 'server03', 'server04']

    with open('peers.json', 'w') as fp:
        json.dump(client_names, fp)

    client_dict = dict()
    server_dict = dict()

    next_result_ID = 0
    next_request_ID = 0
    result_ID_list = []

    isp_log = 'unknown'
    isp_key = 'unknown'

    client_log = 'unknown'
    server_log = 'unknown'

    logging.debug(f'ISP-LOG:{isp_log}')
    logging.debug(f'ISP-KEY:{isp_key}')
    logging.debug(f'Client-LOG:{client_log}')

    init()
    init_clients()
    init_servers()

    for cli in client_dict.values():
        print(cli.to_string())

    start_watchdog()

    print("Dumping feeds...")
    for client in client_dict.values():
        print('------------------------------')
        print(f'dumping feed {client.client_isp_feed}')
        print()
        pcap.dump(client.client_isp_feed)
        print('------------------------------')
        print(f'dumping feed {client.isp_client_feed}')
        print()
        pcap.dump(client.isp_client_feed)

    for server in server_dict.values():
        print('------------------------------')
        print(f'dumping feed {server.isp_server_feed}')
        print()
        pcap.dump(server.isp_server_feed)
        print('------------------------------')
        print(f'dumping feed {server.server_isp_feed}')
        print()
        pcap.dump(server.server_isp_feed)

    with open('client_dump.json', 'w') as fp:
        dump = dict
        for client in client_dict.values():
            json.dump(client.encode(), fp)

    # request = handle_input(input())

# TODO: Refactor
# TODO: Logging
