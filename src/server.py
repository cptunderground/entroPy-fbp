import hashlib
import logging
import multiprocessing
import re
import argparse
import os
import sys
import time

import cbor2

import lib.feed as feed
import lib.pcap as pcap
import lib.crypto as crypto


class sClient():
    def __init__(self, name, E2E_c_s_log, E2E_s_c_log, E2E_s_c_key, highest_request_ID, open_requests):
        self.name = name
        self.E2E_c_s_log = E2E_c_s_log
        self.E2E_s_c_log = E2E_s_c_log
        self.E2E_s_c_key = E2E_s_c_key
        self.highest_request_ID = highest_request_ID
        self.open_requests = open_requests

    def to_string(self):
        return f'{self.name}, {self.E2E_c_s_log}, {self.E2E_s_c_log}, {self.E2E_s_c_key}, {self.highest_request_ID}, {self.open_requests}'


def wr_feed(f, key, msg):
    feed.append_feed(f, key, msg)


def create_feed(name):
    global client_log
    global client_key
    global next_request_ID

    if os.path.exists(f'feeds/{name}/{name}_{args.peer}.pcap') and os.path.exists(
            f'feeds/{name}/{name}_{args.peer}.key'):
        logging.info(f'Feed and key for {name} exist')
        client_key = f'feeds/{name}/{name}_{args.peer}.key'
        client_log = f'feeds/{name}/{name}_{args.peer}.pcap'
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'feeds/{name}'):
            os.mkdir(f'feeds/{name}')
        f = open(f'feeds/{name}/{name}_{args.peer}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'feeds/{name}/{name}_{args.peer}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'feeds/{name}/{name}_{args.peer}.key')
        client_feed = feed.FEED(f'feeds/{name}/{name}_{args.peer}.pcap', fid, signer, True)

        client_log = f'feeds/{name}/{name}_{args.peer}.pcap'
        client_key = f'feeds/{name}/{name}_{args.peer}.key'

        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'ID': next_request_ID,
            'type': 'initiation',
            'source': args.name,
            'destination': args.name,
            'service': 'init',
            'attributes': name
        }
        next_request_ID += 1

        logging.info(f'writing in {client_log}: {feed_entry}')
        client_feed.write(feed_entry)


def init():
    global server_log
    global server_key
    global highest_introduce_ID

    global isp_log

    if os.path.exists(f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.pcap') and os.path.exists(
            f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.key'):
        logging.info(f'Feed and key for {args.server_name} exist')
        server_key = f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.key'
        server_log = f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.pcap'
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'feeds/{args.server_name}'):
            os.mkdir(f'feeds/{args.server_name}')
        f = open(f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.key')
        server_feed = feed.FEED(f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.pcap', fid, signer, True)

        server_log = f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.pcap'
        server_key = f'feeds/{args.server_name}/{args.server_name}_{args.isp_name}.key'

        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'type': 'initiation',
            'source': args.server_name,
            'destination': args.server_name,
            'service': 'init',
            'attributes': args.server_name
        }

        logging.info(f'writing in {server_log}: {feed_entry}')
        server_feed.write(feed_entry)

    # TODO Init on already introduced clients

    logging.info('Initialising from feed...')
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
        # print(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
        # print(f"   hashref={href.hex()}")
        # print(f"   content={e[2]}")

        if isinstance(e[2], dict) and e[2]['type'] == 'introduce':
            logging.debug(f'from init request  ID={e[2]["introduce_ID"]}')

            highest_introduce_ID = max(int(e[2]["introduce_ID"]), highest_introduce_ID)

    p.close()

    p = pcap.PCAP(server_log)
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

        if isinstance(e[2], dict) and e[2]['type'] == 'approved_introduce':
            logging.debug(f'from init request  ID={e[2]["introduce_ID"]}')
            approved.append(e[2]['introduce_ID'])
            if e[2]['result'] != 'already exists':
                add_client(e[2])

    p.close()

    for c in s_client_dict.values():
        client_log = c.E2E_c_s_log
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

            if isinstance(e[2], dict) and e[2]['type'] == 'request':
                request_ID = e[2]["ID"]
                logging.debug(f'ID={e[2]["ID"]}')
                logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                logging.debug(f"   hashref={href.hex()}")
                logging.debug(f"   content={e[2]}")

                c.open_requests.append(request_ID)
                c.highest_request_ID = max(request_ID, c.highest_request_ID)

        p.close()


        p = pcap.PCAP(c.E2E_s_c_log)
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
                request_ID = e[2]["ID"]
                logging.debug(f'ID={e[2]["ID"]}')
                logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                logging.debug(f"   hashref={href.hex()}")
                logging.debug(f"   content={e[2]}")

                if c.open_requests.__contains__(e[2]['ID']):
                    c.open_requests.remove(e[2]['ID'])
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

            if isinstance(e[2], dict) and e[2]['type'] == 'request':
                request_ID = e[2]["ID"]
                logging.debug(f'ID={e[2]["ID"]}')
                logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                logging.debug(f"   hashref={href.hex()}")
                logging.debug(f"   content={e[2]}")

                if c.open_requests.__contains__(request_ID):
                    read_c_request(e[2], c)

        p.close()

    pass


def add_client(log_entry):
    name = log_entry['request_source']
    E2E_server_log = f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.pcap'
    E2E_server_key = f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.key'

    client_e2e_identifier = f'E2E_{name}_{args.server_name}'

    c_s = f'feeds/{name}/{client_e2e_identifier}.pcap'
    s_client_dict[c_s] = sClient(name, c_s, E2E_server_log, E2E_server_key, 0, [])
    sC = s_client_dict[c_s]
    logging.info(sC.to_string())


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

        logging.debug(f'Search ID {ID}')
        logging.debug(f'Actual ID {e[2]["ID"]}')
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
    logging.info(f'got result:{log_entry["result"]} from ID:{log_entry["ID"]} -> {log_entry}')
    logging.info(f'-> {log_entry}')


def handle_new_results():
    logging.info('Handle new results')
    global result_ID_list
    for result_ID in result_ID_list:
        read_result(result_ID)


def handle_introduction():
    global isp_log
    global server_log
    global highest_introduce_ID
    global approved

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

        if isinstance(e[2], dict) and e[2]['type'] == 'introduce':
            logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            logging.debug(f"   hashref={href.hex()}")
            logging.debug(f"   content={e[2]}")

            if e[2]['introduce_ID'] > highest_introduce_ID:
                name = e[2]['attributes']
                result = create_e2e_feed(name)
                send_result(e[2], result)
            elif not approved.__contains__(e[2]['introduce_ID']):
                name = e[2]['attributes']
                result = create_e2e_feed(name)
                send_result(e[2], result)
    p.close()


def send_result(log_entry, result):
    global highest_introduce_ID
    introduce_entry = {
        'introduce_ID': log_entry['introduce_ID'],
        'request_ID': log_entry['request_ID'],
        'request_source': log_entry['request_source'],
        'type': 'approved_introduce',
        'result': result,
        'debug': log_entry['debug']
    }

    logging.info(f'Sending result')
    logging.info(f'Writing in {server_log}: {introduce_entry}')
    wr_feed(server_log, server_key, introduce_entry)
    highest_introduce_ID += 1


def create_e2e_feed(name):
    global s_client_dict

    if os.path.exists(f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.pcap') and os.path.exists(
            f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.key'):
        logging.info(f'E2E feed between {args.server_name} and {name} already exist')
        return 'already exists'
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        f = open(f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.key')
        E2E_server_feed = feed.FEED(f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.pcap', fid, signer, True)

        E2E_server_log = f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.pcap'
        E2E_server_key = f'feeds/{args.server_name}/E2E_{args.server_name}_{name}.key'

        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'type': 'initiation',
            'source': args.server_name,
            'destination': name,
            'service': 'init',
            'attributes': 'E2E'
        }

        logging.info(f'writing in {E2E_server_log}: {feed_entry}')
        E2E_server_feed.write(feed_entry)

        client_e2e_identifier = f'E2E_{name}_{args.server_name}'

        c_s = f'feeds/{name}/{client_e2e_identifier}.pcap'
        s_client_dict[c_s] = sClient(name, c_s, E2E_server_log, E2E_server_key, 0, [])
        logging.info(s_client_dict[c_s].to_string())

        return client_e2e_identifier


def on_created(event):
    logging.debug(f"Created {event.src_path}")


def on_deleted(event):
    logging.critical(f"Deleted: {event.src_path}!")


def on_modified(event):
    global s_client_dict
    logging.debug(f"Modified: {event.src_path}")
    if f'{event.src_path[2:]}' == isp_log:
        handle_introduction()
    else:
        try:
            c = s_client_dict[f'{event.src_path[2:]}']
            read_c_request(c)
            logging.info('works')
        except:
            logging.warning(s_client_dict)
            logging.warning(f'{event.src_path[2:]}')
            logging.warning('file not connected to server changed')



def read_c_request(client: sClient):
    p = pcap.PCAP(client.E2E_c_s_log)
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

            if request_ID > client.highest_request_ID:
                handle_request(e[2], client)
            elif client.open_requests.__contains__(request_ID):
                client.open_requests.remove(request_ID)
                handle_request(e[2], client)

    p.close()


def handle_request(log_entry, client: sClient):
    # TODO implement services
    print('got')
    result = 'got it'
    send_c_result(log_entry, result, client)


def send_c_result(log_entry, result, client: sClient):
    global next_result_ID
    feed_entry = {
        'ID': log_entry['ID'],
        'type': 'result',
        'source': args.server_name,
        'destination': log_entry['source'],
        'service': log_entry['service'],
        'result': result
    }

    logging.info(f'Sending result - writing in {client.E2E_c_s_log}:\n {feed_entry}')
    client.highest_request_ID += 1
    wr_feed(client.E2E_s_c_log, client.E2E_s_c_key, feed_entry)


def on_moved(event):
    logging.critical(f"Moved: {event.src_path} to {event.dest_path}")


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
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-Client for FBP')
    # parser.add_argument('--keyfile')
    # parser.add_argument('pcapfile', metavar='PCAPFILE')
    parser.add_argument('server_name')
    parser.add_argument('isp_name')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    server_log = 'unknown'
    server_key = 'unknown'

    highest_introduce_ID = 0
    approved = []

    s_client_dict = dict()

    isp_log = f'feeds/{args.isp_name}/{args.isp_name}_{args.server_name}.pcap'  #

    init()

    for c in s_client_dict.values():
        logging.info(c.to_string())

    start_watchdog()

    logging.info('dumping feed...')
    pcap.dump(server_log)

# TODO: Refactor
# TODO: Logging
