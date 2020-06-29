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

import lib.feed as feed
import lib.pcap as pcap
import lib.crypto as crypto
from replicator import replicator


class sClient():
    def __init__(self, name, E2E_c_s_log, E2E_c_s_key, E2E_s_c_log, E2E_s_c_key, highest_request_ID, open_requests):
        self.name = name
        self.E2E_c_s_log = E2E_c_s_log
        self.E2E_c_s_key = E2E_c_s_key
        self.E2E_s_c_log = E2E_s_c_log
        self.E2E_s_c_key = E2E_s_c_key
        self.highest_request_ID = highest_request_ID
        self.open_requests = open_requests

    def to_string(self):
        return f'{self.name}, {self.E2E_c_s_log}, {self.E2E_c_s_key}, {self.E2E_s_c_log}, {self.E2E_s_c_key}, {self.highest_request_ID}, {self.open_requests}'

    def asdict(self):
        d = {
            'name': self.name,
            'c_s_feed': self.E2E_c_s_log,
            'c_s_key': self.E2E_c_s_key,
            's_c_feed': self.E2E_s_c_log,
            's_c_key': self.E2E_s_c_key,
        }
        return d


def wr_feed(f, key, msg):
    feed.append_feed(f, key, msg)


def wr_c_s_feed(client: sClient, msg):
    feed.append_feed(client.E2E_c_s_log, client.E2E_c_s_key, msg)


def wr_s_c_feed(client: sClient, msg):
    w = feed.append_feed(client.E2E_s_c_log, client.E2E_s_c_key, msg)
    return w

def create_feed(name):
    global client_log
    global client_key
    global next_request_ID

    if os.path.exists(f'feeds/{name}/{name}_{server_config["ipk"]}.pcap') and os.path.exists(
            f'feeds/{name}/{name}_{server_config["ipk"]}.key'):
        logging.info(f'Feed and key for {name} exist')
        client_key = f'feeds/{name}/{name}_{server_config["ipk"]}.key'
        client_log = f'feeds/{name}/{name}_{server_config["ipk"]}.pcap'
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'feeds/{name}'):
            os.mkdir(f'feeds/{name}')
        f = open(f'feeds/{name}/{name}_{server_config["ipk"]}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'feeds/{name}/{name}_{server_config["ipk"]}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'feeds/{name}/{name}_{server_config["ipk"]}.key')
        client_feed = feed.FEED(f'feeds/{name}/{name}_{server_config["ipk"]}.pcap', fid, signer, True)

        client_log = f'feeds/{name}/{name}_{server_config["ipk"]}.pcap'
        client_key = f'feeds/{name}/{name}_{server_config["ipk"]}.key'

        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'ID': next_request_ID,
            'type': 'initiation',
            'source': server_config['name'],
            'destination': server_config['name'],
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
    global server_config
    global isp_log

    if os.path.exists(f'{server_config["location"]}/{server_config["alias"]}.pcap') and os.path.exists(
            f'{server_config["location"]}/{server_config["key"]}'):
        logging.info(f'Feed and key exist')
        server_key = f'{server_config["location"]}/{server_config["key"]}'
        server_log = f'{server_config["location"]}/{server_config["alias"]}.pcap'

    elif not os.path.exists(f'{server_config["location"]}/{server_config["alias"]}.pcap') and os.path.exists(
            f'{server_config["location"]}/{server_config["key"]}'):
        print("key exists feed not")
        fid, signer = feed.load_keyfile(f'{server_config["location"]}/{server_config["key"]}')
        client_feed = feed.FEED(f'{server_config["location"]}/{server_config["alias"]}.pcap', fid, signer, True)

        server_log = f'{server_config["location"]}/{server_config["alias"]}.pcap'
        server_key = f'{server_config["location"]}/{server_config["key"]}'

        pk = feed.get_public_key(server_key)
        print(pk)
        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'type': 'initiation',
            'alias': server_config['alias'],
            'key': pk,
            'location': server_config['location']
        }


        logging.info(f'writing in {server_log}: {feed_entry}')
        client_feed.write(feed_entry)
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'{server_config["location"]}'):
            os.mkdir(f'{server_config["location"]}')
        f = open(f'{server_config["location"]}/{server_config["key"]}', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'{server_config["location"]}/{server_config["alias"]}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'{server_config["location"]}/{server_config["key"]}')
        client_feed = feed.FEED(f'{server_config["location"]}/{server_config["alias"]}.pcap', fid, signer, True)

        server_log = f'{server_config["location"]}/{server_config["alias"]}.pcap'
        server_key = f'{server_config["location"]}/{server_config["key"]}'

        pk = feed.get_public_key(f'{server_config["location"]}/{server_config["key"]}')
        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'type': 'initiation',
            'alias': server_config['alias'],
            'key': pk,
            'location': server_config['location']
        }


        logging.info(f'writing in {server_log}: {feed_entry}')
        client_feed.write(feed_entry)

    r = replicator.Replicator(f'{server_config["alias"]}.pcap', server_log, server_config['isp_location'])
    r.replicate()
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

        if isinstance(e[2], dict) and (e[2]['type'] == 'introduce' or e[2]['type'] =='request'):
            print(e[2])
            logging.debug(f'from init request  ID={e[2]["introduce_ID"]}')

            highest_introduce_ID = max(int(e[2]["introduce_ID"]), highest_introduce_ID)
            print(highest_introduce_ID)
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
                # add_client(e[2])
                pass

    p.close()

    # TODO init sub clients
    path = server_config['location']
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
                        client = e[2]['client']
                        sclient = sClient(client['name'], client['c_s_feed'], client['c_s_key'], client['s_c_feed'],
                                          client['s_c_key'], 0,
                                          [])
                        s_client_dict[client['name']] = sclient
                        print(sclient)
                    except:
                        pass
            p.close()

    print(s_client_dict)
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
        try:
            e = cbor2.loads(w)
        except:
            logging.warning('A log entry could not be read due to failure of CBOR')
            continue
        href = hashlib.sha256(e[0]).digest()
        e[0] = cbor2.loads(e[0])
        # rewrite the packet's byte arrays for pretty printing:
        e[0] = pcap.base64ify(e[0])
        fid = e[0][0]
        seq = e[0][1]
        if e[2] != None:
            e[2] = cbor2.loads(e[2])

        if isinstance(e[2], dict) and e[2]['type'] == 'introduce':
            print(f'in introduce')

            print(f'detected introduce id:{e[2]["introduce_ID"]}')
            print(f'highest_introduce_ID:{highest_introduce_ID}')
            if e[2]['introduce_ID'] > highest_introduce_ID:
                attributes = e[2]['attributes']
                # create both feeds and return information from both feeds for client
                # wait for input of server, either accept or decline
                print('accept/decline new client:')
                answer = 'accept' #input()
                if answer == 'accept':
                    result = create_e2e_feed(attributes)
                    send_result(e[2], result)
                else:
                    send_result(e[2], 'declined')
        elif isinstance(e[2], dict) and e[2]['type'] == 'detruce':
            logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            logging.debug(f"   hashref={href.hex()}")
            logging.debug(f"   content={e[2]}")

            if e[2]['introduce_ID'] > highest_introduce_ID:
                print(f'logentry:{e[2]}')
                attributes = e[2]['attributes']
                print(f'attributes:{attributes}')
                delete_e2e_feed(attributes)
                send_result(e[2], 'approved')


        elif isinstance(e[2], dict) and e[2]['type'] == 'mux':
            logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            logging.debug(f"   hashref={href.hex()}")
            logging.debug(f"   content={e[2]}")

            if e[2]['introduce_ID'] > highest_introduce_ID:
                request = e[2]['request']
                print(f'SUBCLIENT REQUEST {e[2]}')
                sub_client = s_client_dict[e[2]['source']]
                handle_request(e[2], sub_client)
                highest_introduce_ID += 1





    p.close()


def send_result(log_entry, result):
    global highest_introduce_ID

    introduce_entry = {
        'introduce_ID': log_entry['introduce_ID'],
        'request_ID' : log_entry['request_ID'],
        'type': log_entry['type'],
        'source' : log_entry['source'],
        'destination' : log_entry['destination'],
        'service': log_entry['service'],
        'attributes' : log_entry['attributes'],
        'result': result,
    }

    logging.info(f'Sending result')
    logging.info(f'Writing in {server_log}: {introduce_entry}')
    wr_feed(server_log, server_key, introduce_entry)

    r = replicator.Replicator(f'{server_config["alias"]}.pcap', server_log, server_config['isp_location'])
    r.replicate()

    highest_introduce_ID += 1


def delete_e2e_feed(attributes):
    cpk = attributes['public_key']
    sclient = s_client_dict[cpk]

    os.remove(sclient.E2E_c_s_log)
    os.remove(sclient.E2E_s_c_log)
    os.remove(sclient.E2E_s_c_key)

    s_client_dict.pop(cpk)


def create_e2e_feed(attributes):
    global s_client_dict
    global server_config
    print(attributes)
    server_name = attributes['server']
    client_name = attributes['client']
    cpk = attributes['public_key']

    location = server_config['location']

    s_c_feed = f'{location}/{server_name}_{client_name}.pcap'
    s_c_key = f'{location}/{server_name}_{client_name}.key'

    c_s_feed = f'{location}/{client_name}_{server_name}.pcap'
    c_s_key = None

    '''
    key_pair = crypto.ED25519()
    key_pair.create()
    header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
    keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

    logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
    logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

    f = open(c_s_key, 'w')
    f.write(header)
    f.write(keys)
    f.close()
    '''
    try:
        os.remove(c_s_feed)
    except:
        pass

    #fid, signer = feed.load_keyfile(c_s_key)


    key_pair = crypto.ED25519()
    key_pair.create()
    header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
    keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

    logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
    logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

    f = open(s_c_key, 'w')
    f.write(header)
    f.write(keys)
    f.close()

    try:
        os.remove(s_c_feed)
    except:
        pass

    fid, signer = feed.load_keyfile(s_c_key)
    E2E_server_feed = feed.FEED(s_c_feed, fid, signer, True)
    E2E_client_feed = feed.FEED(c_s_feed, fid, signer, True)

    sclient = sClient(cpk, c_s_feed, c_s_key, s_c_feed, s_c_key, 0, [])
    s_client_dict[cpk] = sclient
    logging.info(s_client_dict[cpk].to_string())

    #cspk = feed.get_public_key(c_s_key)
    scpk = feed.get_public_key(s_c_key)

    #TODO Introduce reverse order
    c_s_feed_entry = {
        'type': 'init',
        'alias': f'{client_name}_{server_name}.pcap',
        'key': None,
        'client': sclient.asdict(),
    }

    s_c_feed_entry = {
        'type': 'init',
        'alias': f'{server_name}_{client_name}.pcap',
        'key': scpk,
        'client': sclient.asdict(),
    }

    E2E_client_feed.write(c_s_feed_entry)
    E2E_server_feed.write(s_c_feed_entry)


    print(f'Clinet Dict: {s_client_dict}')

    ret = server_config['name']

    return ret


def on_created(event):
    logging.debug(f"Created {event.src_path}")


def on_deleted(event):
    logging.critical(f"Deleted: {event.src_path}!")


def on_modified(event):
    global s_client_dict
    print(f'Modified Path: {event.src_path}')
    logging.debug(f"Modified: {event.src_path}")
    if f'{event.src_path}' == isp_log:
        print(f'in if')
        handle_introduction()
    else:
        try:
            c = s_client_dict[f'{event.src_path[2:]}']
            read_c_request(c)
            logging.info('works')
        except:
            logging.warning(f'{event.src_path[2:]}')



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
    print('Handling client request')
    result = 'got it'
    w = log_entry['request']
    e = cbor2.loads(w)
    if e[2] != None:
        e[2] = cbor2.loads(e[2])
    request = e[2]



    c_s_feed = feed.FEED(client.E2E_c_s_log)
    c_s_feed._append(w)



    # handle
    result_entry = {
        'ID': request['ID'],
        'type': 'result',
        'source': server_config['name'],
        'destination': client.name,
        'service': request['service'],
        'attributes': request['attributes'],
        'result': result
    }


    print(result_entry)

    mux_w = wr_s_c_feed(client, result_entry)

    mux_w_loaded = cbor2.loads(mux_w)
    if mux_w_loaded[2] != None:
        mux_w_loaded[0] = cbor2.loads(mux_w_loaded[0])
        mux_w_loaded[0] = pcap.base64ify(mux_w_loaded[0])
        mux_w_loaded[1] = pcap.base64ify(mux_w_loaded[1])
        mux_w_loaded[2] = cbor2.loads(mux_w_loaded[2])

    print(f'S_C_FEED_ENTRY:{mux_w_loaded}')
    mux_result = {
        'introduce_ID': log_entry['introduce_ID'],
        'type': 'mux',
        'result': mux_w
    }

    print(f'Muxed result:{mux_result}')
    wr_feed(server_log, server_key, mux_result)

    r=replicator.Replicator(f'{server_config["alias"]}.pcap', server_log, server_config['isp_location'])
    r.replicate()


def send_c_result(log_entry, result, client: sClient):
    global next_result_ID
    feed_entry = {
        'ID': log_entry['ID'],
        'type': 'result',
        'source': server_config['name'],
        'destination': log_entry['source'],
        'service': log_entry['service'],
        'result': result
    }

    logging.info(f'Sending result - writing in {client.E2E_c_s_log}:\n {feed_entry}')
    client.highest_request_ID += 1
    wr_feed(client.E2E_s_c_log, client.E2E_s_c_key, feed_entry)


def on_moved(event):
    logging.critical(f"Moved: {event.src_path} to {event.destination}")


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

    path = f'{server_config["location"]}'
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    my_observer.start()
    try:
        while True:
            # TODO Read input for detrucing clients

            time.sleep(0.1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


def read_config(fn):
    basic_config = json.loads(open(fn).read())
    try:
        server_public_key = basic_config['spk']
        server_location = basic_config['s_loc']
        isp_public_key = basic_config['ipk']
        isp_location = basic_config['i_loc']
    except:
        logging.critical('Wrong config format')
        exit(1)

    config = {
        "name": server_public_key,
        "ipk": isp_public_key,
        "alias": f'{server_public_key}_{isp_public_key}',
        "key": f'{server_public_key}_{isp_public_key}.key',
        "location": server_location,
        "isp": f'{isp_public_key}_{server_public_key}',
        "isp_location": isp_location
    }
    return config


def extract_client(data):
    print('extracting client')
    try:
        print(s_client_dict)
        client = s_client_dict[data]
        return client
    except Exception as e:
        print(e)
        return -1

def detruce_client(client: sClient):
    global highest_introduce_ID
    print('detrucing client')

    attributes = {
        'public_key' : client.name
    }

    delete_e2e_feed(attributes)

    highest_introduce_ID +=1

    request = {
        'introduce_ID': highest_introduce_ID,
        'type': 'server_detruce',
        'client': client.name
    }

    wr_feed(server_log, server_key, request)
    r = replicator.Replicator(f'{server_config["alias"]}.pcap', server_log, server_config['isp_location'])
    r.replicate()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-Client for FBP')
    # parser.add_argument('--keyfile')
    # parser.add_argument('pcapfile', metavar='PCAPFILE')
    #parser.add_argument('server_name')
    #parser.add_argument('isp_name')
    parser.add_argument('config')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

    server_log = 'unknown'
    server_key = 'unknown'

    highest_introduce_ID = -1

    approved = []

    s_client_dict = dict()

    server_config = read_config(args.config)

    isp_log = f'{server_config["location"]}/{server_config["isp"]}.pcap'
    print(isp_log)
    init()

    for c in s_client_dict.values():
        logging.info(c.to_string())

    import threading


    def get_input():
        while True:
            data = input()  # Something akin to this
            print(f'input::{data}')
            detruce_pattern = r'^--([a-zA-Z0-9 ]+) -([a-zA-Z0-9 ]+)'
            matching_detruce = re.match(detruce_pattern, data)


            if matching_detruce:
                if matching_detruce.group(1).lower() == 'detruce':
                    client = extract_client(matching_detruce.group(2))
                    if client != -1:
                        detruce_client(client)
                    else:
                        pass
            else:
                print(f'not matching pattern: invoke with --service -destination')


    input_thread = threading.Thread(target=get_input)
    input_thread.start()

    start_watchdog()

    logging.info('dumping feed...')
    pcap.dump(server_log)

# TODO: Refactor
# TODO: Logging
