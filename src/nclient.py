import hashlib
import json
import logging
import multiprocessing
import re
import argparse
import os
import sys
import time

import cbor2

import fbp
import lib.feed as feed
import lib.pcap as pcap
import lib.crypto as crypto

# TODO adapt regex for any python structur
from replicator import replicator

full_pattern = r'^service=([a-zA-Z ]+) destination=([a-zA-Z ]+) attrs=\[(([0-9a-zA-Z ][0-9a-zA-Z_ ]*)*([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
full_test_string = 'service=echo      destination=isp  attrs=[te  st, hallo welt, noweqfdnqw] '

short_pattern = r'^--([a-zA-Z0-9 ]+) -([a-zA-Z0-9 ]+) \[(([0-9a-zA-Z ]*[0-9a-zA-Z_\' ]*)([,][0-9a-zA-Z ][0-9a-zA-Z_\' ]*)*)\]'
short_test_string = '--echo      -isp  [te  st, hallo welt, noweqfdnqw]'

delimitor = '---------------------------------------------'


class cServer():
    def __init__(self, name: str, s_c_feed: str, c_s_feed: str, c_s_key: str,
                 highest_introduce_ID: int,
                 open_introduces: list, replicator: replicator.Replicator):
        self.name = name
        self.s_c_feed = s_c_feed
        self.c_s_feed = c_s_feed
        self.c_s_key = c_s_key
        self.highest_introduce_ID = highest_introduce_ID
        self.open_introduces = open_introduces
        self.replicator = replicator

    def to_string(self):
        return f'{self.name}, {self.s_c_feed}, {self.c_s_feed}, {self.c_s_key}, {self.highest_introduce_ID}, ' \
               f'{self.open_introduces}'

    def asdict(self):
        d = {
            'name': self.name,
            's_c_feed': self.s_c_feed,
            'c_s_feed': self.c_s_feed,
            'c_s_key': self.c_s_key,
            'replicator': {
                'name': self.replicator.name,
                'source': self.replicator.source_path,
                'destination': self.replicator.destination
            }

        }
        return d


def handle_input(msg):
    if not isinstance(msg, str):
        msg = str(msg.decode('utf8'))
    logging.debug(f'msg: {msg}')

    matching_full = re.match(full_pattern, msg)
    matching_short = re.match(short_pattern, msg)

    # TODO eval attributes to python structure
    if matching_full:
        service = matching_full.group(1)
        destination = matching_full.group(2)
        attributes_str = matching_full.group(3)
        attributes = attributes_str.split(', ')

        logging.debug(
            f'Detected full: service:{service}, destination:{destination} with the following attributes:{attributes}')

        request = {
            'service': service,
            'destination': destination,
            'attributes': attributes
        }

        return request
        # win.addstr(f"debugging post({msg})")
    elif matching_short:
        service = matching_short.group(1)
        destination = matching_short.group(2)
        attributes_str = matching_short.group(3)
        attributes = eval(attributes_str)

        logging.debug(
            f'Detected short: service:{service}, destination:{destination} with the following attributes:{attributes}')

        request = {
            'service': service,
            'destination': destination,
            'attributes': attributes
        }

        return request
    else:
        if msg.lower() == 'refresh':
            logging.info('Refreshing')
            refresh()
        else:
            logging.warning('Input not matching pattern')
        # win.addstr(f"failed post({msg})")


def refresh():
    global c_server_dict

    handle_new_results()

    for s in c_server_dict.values():
        handle_new_s_results(s)
    pass


def send_request(request: dict):
    global next_request_ID
    global client_log
    global client_key

    global c_server_dict
    # TODO exchange sourece and dest with public keys

    if request['service'] == 'introduce':
        if not request['attributes'] in c_server_dict.keys():
            public_key = create_E2E_feed(request['attributes'])
            attributes = {
                'server': request['attributes'],
                'public_key': public_key
            }

            feed_entry = {
                'ID': next_request_ID,
                'type': 'request',
                'source': args.name,
                'destination': request['destination'],
                'service': request['service'],
                'attributes': attributes
            }
        else:
            logging.warning(f'Feed for {request["attributes"]} already exists')
            return

    elif request['service'] == 'detruce':
        print(request['attributes'])
        if request['attributes'] in c_server_dict.keys():

            public_key = delete_E2E_feed(request['attributes'])

            attributes = {
                'server': request['attributes'],
                'public_key': public_key
            }

            feed_entry = {
                'ID': next_request_ID,
                'type': 'request',
                'source': args.name,
                'destination': request['destination'],
                'service': request['service'],
                'attributes': attributes
            }
        else:
            logging.warning(f'Feed for {request["attributes"]} does not exist')
            return
    else:
        feed_entry = {
            'ID': next_request_ID,
            'type': 'request',
            'source': args.name,
            'destination': request['destination'],
            'service': request['service'],
            'attributes': request['attributes']
        }

    if str(request['destination']).lower() == client_config['ipk']:
        wr_feed(client_log, client_key, feed_entry)
        await_result(feed_entry['ID'])
        next_request_ID += 1
    else:
        # TODO optimize
        if len(c_server_dict) != 0:
            for server in c_server_dict.values():
                if str(request['destination']).lower() == server.name:
                    wr_server_feed(feed_entry, server)
                    await_result(feed_entry['ID'])
                    next_request_ID += 1
                else:
                    logging.warning(f'No server registered for {request["destination"]}, try to introduce first')
        else:
            logging.info('No servers registered')


def wr_feed(f, key, msg):
    logging.info(f'Writing in {f}: {msg}')
    feed.append_feed(f, key, msg)
    replicator.replicate(f'{client_config["location"]}/{client_config["alias"]}.pcap',
                         f'{client_config["isp_location"]}/{client_config["alias"]}.pcap')

def wr_server_feed(msg, server:cServer):
    logging.info(f'Writing in {server.c_s_feed}: {msg}')
    feed.append_feed(server.c_s_feed, server.c_s_key, msg)
    server.replicator.replicate()
def delete_E2E_feed(spk):
    global c_server_dict
    server = c_server_dict[spk]

    pk = feed.get_public_key(server.c_s_key)

    os.remove(server.c_s_feed)
    os.remove(server.c_s_key)
    os.remove(server.s_c_feed)
    c_server_dict.pop(spk)
    print(c_server_dict)
    return pk

def create_E2E_feed(spk):
    global c_server_dict
    cpk = client_config["name"]
    c_location = client_config["location"]
    i_location = client_config["isp_location"]

    key_pair = crypto.ED25519()
    key_pair.create()
    header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
    keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

    logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
    logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

    if not os.path.exists(f'{c_location}'):
        os.mkdir(f'{c_location}')
    f = open(f'{c_location}/{cpk}_{spk}.key', 'w')
    f.write(header)
    f.write(keys)
    f.close()

    try:
        os.remove(f'{c_location}/{cpk}_{spk}.pcap')
    except:
        pass

    fid, signer = feed.load_keyfile(f'{c_location}/{cpk}_{spk}.key')
    E2E_feed = feed.FEED(f'{c_location}/{cpk}_{spk}.pcap', fid, signer, True)

    alias_c_s = f'{c_location}/{cpk}_{spk}.pcap'
    alias_s_c = f'{c_location}/{spk}_{cpk}.pcap'
    key_c_s = f'{c_location}/{cpk}_{spk}.key'
    # TODO exchange sourece and dest with public keys

    rep = replicator.Replicator(f'{cpk}_{spk}.pcap', alias_c_s, i_location)
    cserver = cServer(spk, alias_s_c, alias_c_s, key_c_s, 0, [], rep)
    c_server_dict[spk] = cserver
    print(c_server_dict[spk].to_string())

    feed_entry = {
        'type': 'init',
        'key': feed.get_public_key(key_c_s),
        'cserver': cserver.asdict()
    }
    logging.info(f'writing in {spk}: {feed_entry}')
    E2E_feed.write(feed_entry)
    cserver.replicator.replicate()

    return eval(keys)["public"]


def create_feed():
    global client_log
    global client_key
    global next_request_ID
    global client_config

    if os.path.exists(f'{client_config["location"]}/{client_config["alias"]}.pcap') and os.path.exists(
            f'{client_config["location"]}/{client_config["key"]}'):
        logging.info(f'Feed and key exist')
        client_key = f'{client_config["location"]}/{client_config["key"]}'
        client_log = f'{client_config["location"]}/{client_config["alias"]}.pcap'

    elif not os.path.exists(f'{client_config["location"]}/{client_config["alias"]}.pcap') and os.path.exists(
            f'{client_config["location"]}/{client_config["key"]}'):
        print("key exists feed not")
        fid, signer = feed.load_keyfile(f'{client_config["location"]}/{client_config["key"]}')
        client_feed = feed.FEED(f'{client_config["location"]}/{client_config["alias"]}.pcap', fid, signer, True)

        client_log = f'{client_config["location"]}/{client_config["alias"]}.pcap'
        client_key = f'{client_config["location"]}/{client_config["key"]}'

        pk = feed.get_public_key(client_key)
        print(pk)
        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'type': 'initiation',
            'alias': client_config['alias'],
            'key': pk,
            'location': client_config['location']
        }
        next_request_ID += 1

        logging.info(f'writing in {client_log}: {feed_entry}')
        client_feed.write(feed_entry)
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'{client_config["location"]}'):
            os.mkdir(f'{client_config["location"]}')
        f = open(f'{client_config["location"]}/{client_config["key"]}', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'{client_config["location"]}/{client_config["alias"]}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'{client_config["location"]}/{client_config["key"]}')
        client_feed = feed.FEED(f'{client_config["location"]}/{client_config["alias"]}.pcap', fid, signer, True)

        client_log = f'{client_config["location"]}/{client_config["alias"]}.pcap'
        client_key = f'{client_config["location"]}/{client_config["key"]}'

        pk = feed.get_public_key(f'{client_config["location"]}/{client_config["key"]}')
        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'type': 'initiation',
            'alias': client_config['alias'],
            'key': pk,
            'location': client_config['location']
        }
        next_request_ID += 1

        logging.info(f'writing in {client_log}: {feed_entry}')
        client_feed.write(feed_entry)


def init():
    global next_request_ID
    global highest_result_ID
    global result_ID_list

    create_feed()

    logging.info('Initialising from feeds...')
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
        # print(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
        # print(f"   hashref={href.hex()}")
        # print(f"   content={e[2]}")

        if isinstance(e[2], dict) and e[2]['type'] == 'request':
            logging.debug(f'from init request  ID={e[2]["ID"]}')
            await_result(e[2]['ID'])
            next_request_ID = max(int(e[2]["ID"]), next_request_ID)

    p.close()

    p = pcap.PCAP(isp_log)
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

        if isinstance(e[2], dict) and e[2]['type'] == 'result':
            if result_ID_list.__contains__(e[2]['ID']):
                logging.debug(f'from init result  ID={e[2]["ID"]}')
                logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                logging.debug(f"   hashref={href.hex()}")
                logging.debug(f"   content={e[2]}")

                read_result(e[2]['ID'])

    p.close()

    path = client_config['location']
    print(path)
    for log in os.listdir(path):
        print(os.path.isfile(os.path.join(path, log)))
        if os.path.isfile(os.path.join(path, log)) and log.endswith(".pcap"):
            print(log)
            p = pcap.PCAP(f'{path}/{log}')
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


                if isinstance(e[2], dict) and e[2]['type'] == 'init':
                    print(e[2])
                    try:
                        server = e[2]['cserver']
                        rep = e[2]['cserver']['replicator']
                        creplicator = replicator.Replicator(rep['name'], rep['source'],rep['destination'])
                        cserver = cServer(server['name'], server['s_c_feed'], server['c_s_feed'], server['c_s_key'], 0,
                                          [], creplicator)
                        c_server_dict[server['name']] = cserver
                        print(server)
                    except:
                        pass
            p.close()
    print(c_server_dict)

    for s in c_server_dict.values():
        p = pcap.PCAP(s.c_s_feed)
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
            # print(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            # print(f"   hashref={href.hex()}")
            # print(f"   content={e[2]}")

            if isinstance(e[2], dict) and e[2]['type'] == 'request':
                logging.debug(f'from init request  ID={e[2]["ID"]}')
                await_result(e[2]['ID'])
                next_request_ID = max(int(e[2]["ID"]), next_request_ID)

        p.close()

    next_request_ID += 1
    logging.info(f'Highest ID: {next_request_ID}')
    pass


def await_result(ID):
    global result_ID_list
    result_ID_list.append(ID)


def clear_await(ID):
    global result_ID_list
    result_ID_list.remove(ID)


def read_c_result(ID, server: cServer):
    global result_ID_list

    p = pcap.PCAP(server.s_c_feed)
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

        if isinstance(e[2], dict) and e[2]['type'] == 'result':
            if e[2]['ID'] == ID:
                logging.debug(f'from read_result  ID={e[2]["ID"]}')
                logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                logging.debug(f"   hashref={href.hex()}")
                logging.debug(f"   content={e[2]}")
                if result_ID_list.__contains__(ID):
                    clear_await(ID)
                handle_result(e[2])
                return True

    p.close()
    return False


def read_result(ID):
    global result_ID_list

    p = pcap.PCAP(isp_log)
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

        if isinstance(e[2], dict) and e[2]['type'] == 'result':
            if e[2]['ID'] == ID:
                logging.debug(f'from read_result  ID={e[2]["ID"]}')
                logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                logging.debug(f"   hashref={href.hex()}")
                logging.debug(f"   content={e[2]}")
                if result_ID_list.__contains__(ID):
                    clear_await(ID)
                handle_result(e[2])
                return True

    p.close()
    return False


def handle_result(log_entry):
    if log_entry['service'] == 'introduce':
        logging.info(f'Got introduce result from ID:{log_entry["ID"]}')
        logging.info(f'-> {log_entry}')

        if log_entry['result'] != 'already exists':
            pass
    else:
        logging.info(f'got result:{log_entry["result"]} from ID:{log_entry["ID"]} -> {log_entry}')
        logging.info(f'-> {log_entry}')


def handle_new_results():
    logging.info('Handle new results')
    global result_ID_list
    for result_ID in result_ID_list:
        read_result(result_ID)


def handle_new_s_results(server: cServer):
    global result_ID_list
    for result_ID in result_ID_list:
        read_c_result(result_ID, server)


def on_created(event):
    logging.debug(f"Created: {event.src_path}")


def on_deleted(event):
    logging.critical(f"Deleted: {event.src_path}!")


def on_modified(event):
    global c_server_dict
    logging.debug(f"Modified: {event.src_path}")

    # if f'{event.src_path[2:]}' == isp_log:

    if f'{event.src_path[2:]}' == f'{client_config["location"]}/{client_config["isp"]}.pcap':
        handle_new_results()
    else:
        print(f'{event.src_path[2:]}')
        for s in c_server_dict.values():
            if s.s_c_feed == f'{event.src_path[2:]}':
                print('for works')
                handle_new_s_results(s)
        # s = c_server_dict[f'{event.src_path[2:]}']
        # handle_new_s_results(s)


def on_moved(event):
    logging.critical(f"Moved: {event.src_path} to {event.destination}")


def start_watchdog(method_to_call):
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

    path = client_config['location']
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    my_observer.start()
    try:
        while True:
            method_to_call()
            time.sleep(1)
            logging.info('next imput:')
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


def read_config(fn):
    basic_config = json.loads(open(fn).read())
    try:
        client_public_key = basic_config['cpk']
        client_location = basic_config['c_loc']
        isp_public_key = basic_config['ipk']
        isp_location = basic_config['i_loc']
    except:
        logging.critical('Wrong config format')
        exit(1)

    config = {
        "name": client_public_key,
        "ipk": isp_public_key,
        "alias": f'{client_public_key}_{isp_public_key}',
        "key": f'{client_public_key}_{isp_public_key}.key',
        "location": client_location,
        "isp": f'{isp_public_key}_{client_public_key}',
        "isp_location": isp_location
    }
    return config


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-Client for FBP')
    # parser.add_argument('--keyfile')
    # parser.add_argument('pcapfile', metavar='PCAPFILE')
    parser.add_argument('name')
    parser.add_argument('peer')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    next_request_ID = 0
    highest_result_ID = 0
    result_ID_list = []
    client_log = 'unknown'
    client_key = 'unknown'

    #

    c_server_dict = dict()

    client_config = read_config("fff-conf.json")
    print(client_config)

    isp_log = f'{client_config["location"]}/{client_config["isp"]}.pcap'
    init()

    logging.info("Type Request {--service -destination [attributes]}")

    request = {}


    # request = handle_input(input())

    def r():
        inp = input()
        request = handle_input(inp)
        if request != None:
            send_request(request)
        else:
            print('')


    start_watchdog(r)

    logging.info('dumping feed...')
    pcap.dump(client_log)
