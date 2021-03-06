import argparse
import hashlib
import json
import logging
import os

import cbor2
import services

import lib.crypto as crypto
import lib.feed as feed
import lib.pcap as pcap
from replicator import replicator


class Server():
    '''
    Holds all information about connected server - is the result of the contract or even can be seen as contract
    '''

    def __init__(self, name: str, server_isp_feed: str, isp_server_feed: str, isp_server_key: str,
                 highest_introduce_ID: int,
                 open_introduces: list, replicator: replicator.Replicator):
        self.name = name
        self.server_isp_feed = server_isp_feed
        self.isp_server_feed = isp_server_feed
        self.isp_server_key = isp_server_key
        self.highest_introduce_ID = highest_introduce_ID
        self.open_introduces = open_introduces
        self.config = {}
        self.replicator = replicator

    def to_string(self):
        return f'{self.name}, {self.server_isp_feed}, {self.isp_server_feed}, {self.isp_server_key}, {self.highest_introduce_ID}, {self.open_introduces}'

    def encode(self):
        return self.__dict__

    def asdict(self):
        d = {
            'name': self.name,
            'server_isp_feed': self.server_isp_feed,
            'isp_server_feed': self.isp_server_feed,
            'isp_server_key': self.isp_server_key,
            'replicator': {
                'name': self.replicator.name,
                'source': self.replicator.source_path,
                'destination': self.replicator.destination
            }

        }
        return d


class Client():
    '''
    Holds all information about connected client - is the result of the contract or even can be seen as contract
    '''

    def __init__(self, name: str, client_isp_feed: str, isp_client_feed: str, isp_client_key: str,
                 highest_request_ID: int, open_requests: list, replicator: replicator.Replicator):
        self.name = name
        self.client_isp_feed = client_isp_feed
        self.isp_client_feed = isp_client_feed
        self.isp_client_key = isp_client_key
        self.highest_request_ID = highest_request_ID
        self.open_requests = open_requests
        self.config = {}
        self.replicator = replicator

    def to_string(self):
        return f'{self.name}, {self.client_isp_feed}, {self.isp_client_feed}, {self.isp_client_key}, {self.highest_request_ID}, {self.open_requests}'

    def encode(self):
        return self.__dict__

    def asdict(self):
        d = {
            'name': self.name,
            'client_isp_feed': self.client_isp_feed,
            'isp_client_feed': self.isp_client_feed,
            'isp_client_key': self.isp_client_key,
            'replicator': {
                'name': self.replicator.name,
                'source': self.replicator.source_path,
                'destination': self.replicator.destination
            }

        }
        return d


def init():
    '''
    reads the contracts and generates feeds and keys for them, also stores this in each case in a client/server class
    :return:
    '''
    global client_names
    global client_dict

    global server_names
    global server_dict

    global isp_config
    name = isp_config['ipk']

    # Create isp_client feeds
    for key in isp_config['client_keys']:
        client_config = {
            "cpk": isp_config[key]['cpk'],

            "alias": f'{isp_config["ipk"]}_{isp_config[key]["cpk"]}.pcap',
            "key": f'{isp_config["ipk"]}_{isp_config[key]["cpk"]}.key',
            "c_location": f'{isp_config[key]["c_location"]}'
        }

        cpk = isp_config[key]['cpk']
        ipk = isp_config["ipk"]
        alias_s_i = f'{isp_config[key]["cpk"]}_{isp_config["ipk"]}.pcap'
        alias_i_s = f'{isp_config["ipk"]}_{isp_config[key]["cpk"]}.pcap'
        key_i_s = f'{isp_config["ipk"]}_{isp_config[key]["cpk"]}.key'
        i_location = isp_config["location"]
        s_location = isp_config[key]["c_location"]

        # if feeds exist just stores them
        if os.path.exists(f'{i_location}/{alias_i_s}') and os.path.exists(f'{i_location}/{key_i_s}'):

            logging.info(f'Feed and key for {name} exist')
            # isp to client feeds
            isp_client_key = f'{i_location}/{key_i_s}'
            isp_client_feed = f'{i_location}/{alias_i_s}'
            client_isp_feed = f'{i_location}/{alias_s_i}'

            rep = replicator.Replicator(alias_i_s, isp_client_feed, s_location)

            client_class = Client(cpk, client_isp_feed, isp_client_feed, isp_client_key, -1, [], rep)

            client_class.config = isp_config[key]
            client_dict[key] = client_class

            logging.info(f'ISP-FEED:{isp_client_feed}')
            logging.info(f'ISP-KEY:{isp_client_key}')
            client_class.replicator.replicate()

            # print(client_class.to_string())
        # if only key file exists - generates feeds and stores them
        elif not os.path.exists(f'{i_location}/{alias_i_s}') and os.path.exists(f'{i_location}/{key_i_s}'):

            # print("key exists feed not")
            fid, signer = feed.load_keyfile(f'{i_location}/{key_i_s}')
            client_feed = feed.FEED(f'{i_location}/{alias_i_s}', fid, signer, True)

            isp_client_feed = f'{i_location}/{alias_i_s}'
            isp_client_key = f'{i_location}/{key_i_s}'
            client_isp_feed = f'{i_location}/{alias_s_i}'
            pk = feed.get_public_key(isp_client_key)
            # print(pk)

            rep = replicator.Replicator(alias_i_s, isp_client_feed, s_location)

            client_class = Client(cpk, client_isp_feed, isp_client_feed, isp_client_key, -1, [], rep)
            client_class.config = isp_config[key]
            client_dict[key] = client_class

            feed_entry = {
                'type': 'init',
                'alias': alias_i_s,
                'key': cpk,
                'client': client_class.asdict(),
                'location': i_location
            }

            logging.info(f'writing in {isp_config}: {feed_entry}')
            # print(isp_client_feed)
            client_feed.write(feed_entry)
            client_class.replicator.replicate()


        # generates everything
        else:
            logging.info(f'Feed for {name} does not exist')
            logging.info(f'Creating feed for {name}')
            key_pair = crypto.ED25519()
            key_pair.create()
            header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
            keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            logging.warning("# new ED25519 key pair: ALWAYS keep the private key as a secret")
            logging.warning('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            if not os.path.exists(f'{i_location}'):
                os.mkdir(f'{i_location}')
            f = open(f'{i_location}/{key_i_s}', 'w')
            f.write(header)
            f.write(keys)
            f.close()

            try:
                os.remove(f'{i_location}/{alias_i_s}')
            except:
                pass

            isp_client_feed = f'{i_location}/{alias_i_s}'
            isp_client_key = f'{i_location}/{key_i_s}'
            client_isp_feed = f'{i_location}/{alias_s_i}'

            rep = replicator.Replicator(alias_i_s, isp_client_feed, s_location)

            client_class = Client(cpk, client_isp_feed, isp_client_feed, isp_client_key, -1, [], rep)
            client_class.config = isp_config[key]
            client_dict[key] = client_class

            logging.info(f'Created Feed for {name} in {isp_client_feed}')
            logging.info(f'Created Key for {name} in {isp_client_key}')

            pk = feed.get_public_key(isp_client_key)

            feed_entry = {
                'type': 'init',
                'alias': alias_i_s,
                'key': cpk,
                'client': client_class.asdict(),
                'location': i_location
            }

            logging.info(f'Writing in {isp_client_feed}: {feed_entry}')
            fid, signer = feed.load_keyfile(isp_client_key)
            client_feed = feed.FEED(isp_client_feed, fid, signer,
                                    True)
            client_feed.write(feed_entry)
            client_class.replicator.replicate()
            # services.announce_all_services(client_class)

    # creates isp-server feeds the same way as above for clients
    for key in isp_config['server_keys']:
        spk = isp_config[key]['spk']
        ipk = isp_config["ipk"]
        alias_s_i = f'{isp_config[key]["spk"]}_{isp_config["ipk"]}.pcap'
        alias_i_s = f'{isp_config["ipk"]}_{isp_config[key]["spk"]}.pcap'
        key_i_s = f'{isp_config["ipk"]}_{isp_config[key]["spk"]}.key'
        i_location = isp_config["location"]
        s_location = isp_config[key]["s_location"]

        if os.path.exists(f'{i_location}/{alias_i_s}') and os.path.exists(f'{i_location}/{key_i_s}'):

            logging.info(f'Feed and key for {name} exist')
            # isp to client feeds
            isp_server_key = f'{i_location}/{key_i_s}'
            isp_server_feed = f'{i_location}/{alias_i_s}'
            server_isp_feed = f'{i_location}/{alias_s_i}'

            rep = replicator.Replicator(alias_i_s, isp_server_feed, s_location)

            server_class = Server(spk, server_isp_feed, isp_server_feed, isp_server_key, 0, [], rep)

            server_class.config = isp_config[key]
            server_dict[key] = server_class

            logging.info(f'ISP-FEED:{isp_server_feed}')
            logging.info(f'ISP-KEY:{isp_server_key}')
            server_class.replicator.replicate()

            # print(server_class.to_string())

        elif not os.path.exists(f'{i_location}/{alias_i_s}') and os.path.exists(f'{i_location}/{key_i_s}'):

            # print("key exists feed not")
            fid, signer = feed.load_keyfile(f'{i_location}/{key_i_s}')
            server_feed = feed.FEED(f'{i_location}/{alias_i_s}', fid, signer, True)

            isp_server_feed = f'{i_location}/{alias_i_s}'
            isp_server_key = f'{i_location}/{key_i_s}'
            server_isp_feed = f'{i_location}/{alias_s_i}'
            pk = feed.get_public_key(isp_server_key)
            # print(pk)

            rep = replicator.Replicator(alias_i_s, isp_server_feed, s_location)

            server_class = Server(spk, server_isp_feed, isp_server_feed, isp_server_key, 0, [], rep)
            server_class.config = isp_config[key]
            server_dict[key] = server_class

            feed_entry = {
                'type': 'init',
                'alias': alias_i_s,
                'key': spk,
                'server': server_class.asdict(),
                'location': i_location
            }

            logging.info(f'writing in {isp_config}: {feed_entry}')

            server_feed.write(feed_entry)
            server_class.replicator.replicate()


        else:
            logging.info(f'Feed for {name} does not exist')
            logging.info(f'Creating feed for {name}')
            key_pair = crypto.ED25519()
            key_pair.create()
            header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
            keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            logging.warning("# new ED25519 key pair: ALWAYS keep the private key as a secret")
            logging.warning('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            if not os.path.exists(f'{i_location}'):
                os.mkdir(f'{i_location}')
            f = open(f'{i_location}/{key_i_s}', 'w')
            f.write(header)
            f.write(keys)
            f.close()

            try:
                os.remove(f'{i_location}/{alias_i_s}')
            except:
                pass

            isp_server_feed = f'{i_location}/{alias_i_s}'
            isp_server_key = f'{i_location}/{key_i_s}'
            server_isp_feed = f'{i_location}/{alias_s_i}'

            rep = replicator.Replicator(alias_i_s, isp_server_feed, s_location)

            server_class = Server(spk, server_isp_feed, isp_server_feed, isp_server_key, 0, [], rep)
            server_class.config = isp_config[key]
            server_dict[key] = server_class

            logging.info(f'Created Feed for {name} in {isp_server_feed}')
            logging.info(f'Created Key for {name} in {isp_server_key}')

            pk = feed.get_public_key(isp_server_key)

            feed_entry = {
                'type': 'init',
                'alias': alias_i_s,
                'key': spk,
                'server': server_class.asdict(),
                'location': i_location
            }

            logging.info(f'Writing in {isp_server_feed}: {feed_entry}')
            fid, signer = feed.load_keyfile(isp_server_key)
            server_feed = feed.FEED(isp_server_feed, fid, signer,
                                    True)
            server_feed.write(feed_entry)
            server_class.replicator.replicate()
            # services.announce_all_services(client_class)


def init_clients():
    '''
    this method initialises client-isp and isp-client feeds if they are already generated.
    as well as sub clients, better said the connection for server-client and client-server feeds
    :return:
    '''
    global client_dict
    global client_names

    logging.info('init_clients')

    path = isp_config['location']
    for log in os.listdir(path):
        if os.path.isfile(os.path.join(path, log)) and log.endswith(".pcap"):
            p = pcap.PCAP(f'{path}/{log}')
            p.open('r')
            for w in p:

                e = cbor2.loads(w)

                e[0] = cbor2.loads(e[0])

                e[0] = pcap.base64ify(e[0])

                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                if isinstance(e[2], dict) and e[2]['type'] == 'init':
                    try:
                        sub_client = e[2]['sub_client']
                        rep = e[2]['sub_client']['replicator']
                        creplicator = replicator.Replicator(rep['name'], rep['source'], rep['destination'])
                        s_client = Client(sub_client['name'], sub_client['client_isp_feed'],
                                          sub_client['isp_client_feed'], sub_client['isp_client_key'], -1,
                                          [], creplicator)
                        sub_client_dict[sub_client['name']] = s_client
                        logging.info(f'SUBCLIENT:{s_client.to_string()}')
                    except:
                        logging.info('No sub client found')
            p.close()

    for name in isp_config['client_keys']:
        try:
            client = client_dict[name]
        except:
            logging.critical(f'Client: {name} does not exist')

        if os.path.exists(f'{client.client_isp_feed}'):

            p = pcap.PCAP(client.client_isp_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

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

                    client.open_requests.append(request_ID)
                    client.highest_request_ID = max(request_ID, client.highest_request_ID)

            p.close()

            p = pcap.PCAP(client.isp_client_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

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

                    if client.open_requests.__contains__(e[2]['ID']):
                        client.open_requests.remove(e[2]['ID'])
                        # read_request(e[2])
                    else:
                        pass

            p.close()

            p = pcap.PCAP(client.client_isp_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

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

                    if client.open_requests.__contains__(request_ID):
                        read_request(e[2], client)

            p.close()



        else:
            logging.critical(f'Feed for {name} does not exist')

            pass

    for name in sub_client_dict.keys():
        try:
            client = sub_client_dict[name]
        except:
            logging.critical(f'Client: {name} does not exist')

        if os.path.exists(f'{client.client_isp_feed}'):

            p = pcap.PCAP(client.client_isp_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

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

                    client.open_requests.append(request_ID)
                    client.highest_request_ID = max(request_ID, client.highest_request_ID)

            p.close()

            p = pcap.PCAP(client.isp_client_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

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

                    if client.open_requests.__contains__(e[2]['ID']):
                        client.open_requests.remove(e[2]['ID'])
                        # read_request(e[2])
                    else:
                        pass

            p.close()

            p = pcap.PCAP(client.client_isp_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

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

                    if client.open_requests.__contains__(request_ID):
                        read_request(e[2], client)

            p.close()



        else:
            logging.critical(f'Feed for {name} does not exist')

            pass


def init_servers():
    '''
    same for the server-isp and isp-server feeeds
    :return:
    '''
    global server_dict
    global server_names

    for server in server_dict.values():

        if os.path.exists(f'{server.isp_server_feed}') and os.path.exists(f'{server.server_isp_feed}'):

            p = pcap.PCAP(server.isp_server_feed)
            p.open('r')
            for w in p:

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

                if isinstance(e[2], dict) and 'introduce_ID' in e[2].keys():
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

                e = cbor2.loads(w)
                href = hashlib.sha256(e[0]).digest()
                e[0] = cbor2.loads(e[0])

                e[0] = pcap.base64ify(e[0])
                fid = e[0][0]
                seq = e[0][1]
                if e[2] != None:
                    e[2] = cbor2.loads(e[2])

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


def send_result(log_entry, result, client: Client):
    '''
    This method takes a request, as well as its result and a client, where the destination feed is extracted.
    Writes the result in the feed and replicates it.
    :param log_entry: the request
    :param result:  the result for the request
    :param client:  the client contract
    :return:
    '''
    global next_result_ID
    feed_entry = {
        'ID': log_entry['ID'],
        'type': 'result',
        'service': log_entry['service'],
        'result': result
    }

    logging.info(f'Sending result - writing in {client.isp_client_feed}:\n {feed_entry}')
    client.highest_request_ID += 1
    wr_feed(client.isp_client_feed, client.isp_client_key, feed_entry)
    client.replicator.replicate()
    logging.debug('Result sent')


def send_request(request: dict):
    '''
    Same as in the client, the ISP can request services from the client. Works as the send_request in the clients code
    :param request:
    :return:
    '''
    global next_request_ID
    global server_log

    # TODO exchange sourece and dest with public keys
    feed_entry = {
        'ID': next_request_ID,
        'type': 'request',
        'source': isp_config['ipk'],
        'destination': request['destination'],
        'service': request['service'],
        'attributes': request['attributes']
    }
    next_request_ID += 1

    logging.info(f'writing in {isp_log}:\n{feed_entry}')
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


def invalid_server(log_entry, client: Client):
    logging.warning("INVALID SERVER")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'server', client)


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
    '''
    This function takes the request, evaluates its fields and handles the request by invoking the demanded service
    :param log_entry: the request
    :param client: the contract of the "source" feed
    :return:
    '''
    if log_entry['ID'] == None:
        invalid_format(log_entry, client)
    elif log_entry['type'] == None:
        invalid_format(log_entry, client)
    elif log_entry['service'] == None:
        invalid_format(log_entry, client)
    else:
        logging.debug(log_entry)
        if log_entry['service'] == 'introduce':
            logging.debug('INTRODUCE')
            read_introduce(log_entry, client)

        elif log_entry['service'] == 'detruce':
            logging.debug('DETRUCE')
            read_detruce(log_entry, client)

        elif log_entry['service'] == 'servicecatalog':

            try:
                logging.debug(f'Evaluating service')
                f = eval(f'services.{log_entry["service"]}')
                result = f(log_entry['attributes'])
                send_result(log_entry, result, client)
            except:
                invalid_service(log_entry, client)

        else:
            try:
                logging.debug(f'Evaluating service')
                logging.debug(log_entry['service'])
                '''
                Here the best practice is shown, by just evaluating the service and passing the attributes.
                '''
                f = eval(f'services.Service.{log_entry["service"]}')
                result = f(log_entry['attributes'])
                send_result(log_entry, result, client)
            except:
                invalid_service(log_entry, client)


def delete_E2E_feed(pk):
    '''
    By deleting the contract and feeds, as well as keys, the connection is ended after a detruce
    :param pk: key or name of the peer which ends a contract
    :return:
    '''
    logging.info(f'Deleting {pk} from sub_client_dict:{sub_client_dict}')
    try:
        sub_client = sub_client_dict[pk]

        try:
            os.remove(sub_client.client_isp_feed)
        except:
            logging.warning(f'could not delete file client-isp:{sub_client.client_isp_feed}')
        try:
            os.remove(sub_client.isp_client_key)
        except:
            logging.warning(f'could not delete file:{sub_client.isp_client_key}')
        try:
            os.remove(sub_client.isp_client_feed)
        except:
            logging.warning(f'could not delete file isp-client {sub_client.isp_client_feed}')
    except:
        pass
    try:
        sub_client_dict.pop(pk)
    except:
        pass


def create_E2E_feed(server: Server, client: Client):
    '''
    On a introduce approval, the ISP creates the Server-Client feed, it has all informations in the contracts.
    :param server: contract with server
    :param client: contract with client
    :return:
    '''
    cpk = client.name
    spk = server.name
    location = isp_config["location"]

    try:
        os.remove(f'{location}/{spk}_{cpk}.pcap')
    except:
        pass

    fid, signer = feed.load_keyfile(client.isp_client_key)  # f'{location}/{spk}_{cpk}.key')
    E2E_feed = feed.FEED(f'{location}/{spk}_{cpk}.pcap', fid, signer, True)

    alias_c_s = f'{location}/{cpk}_{spk}.pcap'
    alias_s_c = f'{location}/{spk}_{cpk}.pcap'
    # key_s_c = f'{location}/{spk}_{cpk}.key'

    rep = replicator.Replicator(f'{spk}_{cpk}.pcap', alias_s_c, isp_config[cpk]["c_location"])

    # very very dirty hack...
    # while cpk in sub_client_dict.keys():
    #   cpk = str(cpk) + str(cpk)
    identity = f'{cpk}_{spk}'
    sub_client = Client(identity, alias_c_s, alias_s_c, None, client.highest_request_ID + 1, [], rep)
    sub_client_dict[identity] = sub_client

    feed_entry = {
        'type': 'init',
        'key': None,
        'sub_client': sub_client.asdict()
    }
    logging.info(f'writing in {spk}: {feed_entry}')
    E2E_feed.write(feed_entry)

    sub_client.replicator.replicate()


def read_detruce(log_entry, client: Client):
    '''
    This is the detruce-service
    :param log_entry: detruce-requests
    :param client: contract which has to be ended
    :return:
    '''
    server = server_dict[log_entry['attributes']['server']]
    pk = log_entry['attributes']['public_key']

    # deleting feeds and keys
    delete_E2E_feed(f'{client.name}_{server.name}')

    # send_result(log_entry, client.name, client)

    attributes = {
        'server': log_entry['attributes']['server'],
        'client': log_entry['attributes']['client'],
        'public_key': pk
    }

    # forming request for server.
    request = {
        "introduce_ID": server.highest_introduce_ID,
        'request_ID': log_entry['ID'],
        "type": 'detruce',
        "source": pk,
        'destination': server.name,
        'service': 'detruce',
        'attributes': attributes
    }

    wr_feed(server.isp_server_feed, server.isp_server_key, request)
    server.open_introduces.append(server.highest_introduce_ID)
    server.highest_introduce_ID += 1
    server.replicator.replicate()


def read_introduce(log_entry, client: Client):
    '''
    This is the introduce-service
    :param log_entry: introduce-requests
    :param client: participant information for new contract
    :return:
    '''
    # answer
    try:
        server = server_dict[log_entry['attributes']['server']]
        c_pk = log_entry['attributes']['public_key']
        c_pk = f'{c_pk}_{server.name}'
    except:
        invalid_server(log_entry, client)
        return

    # while c_pk in sub_client_dict.keys():
    #    c_pk = str(c_pk) + str(c_pk)
    # pass pk to server
    # pk = create_E2E_feed(server, client, c_pk)

    # dont send any answer yet
    # send_result(log_entry, pk, client)

    attributes = {
        'server': log_entry['attributes']['server'],
        'client': log_entry['attributes']['client'],
        'public_key': c_pk
    }

    request = {
        "introduce_ID": server.highest_introduce_ID,
        "request_ID": log_entry['ID'],
        "type": 'introduce',
        "source": c_pk,
        'destination': server.name,
        'service': 'introduce',
        'attributes': attributes
    }

    wr_feed(server.isp_server_feed, server.isp_server_key, request)
    server.open_introduces.append(server.highest_introduce_ID)
    server.highest_introduce_ID += 1
    server.replicator.replicate()

    '''
    if log_entry['ID'] > client.highest_request_ID:

        introduce_entry = {
            'introduce_ID': server.highest_introduce_ID,
            'request_ID': log_entry['ID'],
            'request_source': client.name,
            'type': 'introduce',
            'attributes': client.name
        }

        # send introduce
        wr_feed(server.isp_server_feed, server.isp_server_key, introduce_entry)
        server.open_introduces.append(server.highest_introduce_ID)
        server.highest_introduce_ID += 1
        client.highest_request_ID += 1
    else:
        logging.debug(f'ALREADY HANDLED: {log_entry}')
    '''


def server_incoming(server: Server):
    '''
    This method is invoked on feed change of the servers feed it combines read_request and read_result for a server.
    Since all communication is over a single feed
    :param server: the contract the feed belongs to
    :return:
    '''
    global client_dict

    logging.debug('REACHED APPROVAL STATE')
    logging.debug(server.server_isp_feed)
    p = pcap.PCAP(server.server_isp_feed)
    p.open('r')
    for w in p:

        try:
            e = cbor2.loads(w)
        except:
            logging.critical('cbor2 loader failed')
            continue
        href = hashlib.sha256(e[0]).digest()
        e[0] = cbor2.loads(e[0])

        e[0] = pcap.base64ify(e[0])
        fid = e[0][0]
        seq = e[0][1]
        if e[2] != None:
            e[2] = cbor2.loads(e[2])

        if e[2]['type'] != 'initiation':
            logging.debug(e[2])
            logging.debug(f'for mux introduce id:{e[2]["introduce_ID"]},{server.highest_introduce_ID}')

        # read introduce result
        if isinstance(e[2], dict) and e[2]['type'] == 'introduce' and server.open_introduces.__contains__(
                e[2]['introduce_ID']):

            logging.info(f'Log entry: {e}')

            client = client_dict[str(e[2]['source'])[0:6]]

            result = e[2]['result']

            create_E2E_feed(server, client)

            feed_entry = {
                'ID': e[2]['request_ID'],
                'type': 'result',
                'source': isp_config['ipk'],
                'destination': 'does not matter',
                'service': 'introduce',
                'result': result,
            }

            logging.info(f'Sending INTRODUCTION result')
            logging.info(f'Writing in {client.isp_client_feed}:\n'
                         f'{feed_entry}')
            server.open_introduces.remove(e[2]['introduce_ID'])
            wr_feed(client.isp_client_feed, client.isp_client_key, feed_entry)
            if client.open_requests.__contains__(e[2]['request_ID']):
                client.open_requests.remove(e[2]['request_ID'])
            client.replicator.replicate()

        # read detruce result
        if isinstance(e[2], dict) and e[2]['type'] == 'detruce' and server.open_introduces.__contains__(
                e[2]['introduce_ID']):
            logging.debug(f'DETERUCE LOG:{e[2]}')
            logging.info(f'Log entry: {e}')

            client = client_dict[e[2]['source']]

            result = e[2]['result']

            feed_entry = {
                'ID': e[2]['request_ID'],
                'type': 'result',
                'source': isp_config['ipk'],
                'destination': 'does not matter',
                'service': 'detruce',
                'result': result,
            }

            logging.info(f'Sending INTRODUCTION result')
            logging.info(f'Writing in {client.isp_client_feed}:\n'
                         f'{feed_entry}')
            server.open_introduces.remove(e[2]['introduce_ID'])
            wr_feed(client.isp_client_feed, client.isp_client_key, feed_entry)
            client.highest_request_ID = e[2]['request_ID']
            if client.open_requests.__contains__(e[2]['request_ID']):
                client.open_requests.remove(e[2]['request_ID'])
            client.replicator.replicate()

        # read server request to detruce
        if isinstance(e[2], dict) and e[2]['type'] == 'server_detruce' and e[2][
            'introduce_ID'] + 1 > server.highest_introduce_ID:
            logging.info(f'Log entry: {e}')

            logging.debug('reached server_detruce')
            key = e[2]['client']
            sub_client = sub_client_dict[key]
            delete_E2E_feed(key)

            client = client_dict[str(key)[0:6]]
            logging.debug(f'SUBCLID:{sub_client.highest_request_ID}')
            logging.debug(f'CLID:{client.highest_request_ID}')
            ID = max(sub_client.highest_request_ID, client.highest_request_ID)
            client.highest_request_ID = ID + 1
            server.highest_introduce_ID += 1

            request = {
                'ID': client.highest_request_ID,
                'introduce_ID': e[2]['introduce_ID'],
                'type': 'request',
                'service': 'detruce',
                'attributes': server.name
            }

            wr_feed(client.isp_client_feed, client.isp_client_key, request)
            client.replicator.replicate()

        # read a multiplexed log entry
        if isinstance(e[2], dict) and e[2]['type'] == 'mux' and e[2]['introduce_ID'] == server.highest_introduce_ID - 1:
            logging.info(f'Log entry: {e}')

            result = e[2]['result']

            demux_result = cbor2.loads(result)
            if demux_result[2] != None:
                demux_result[0] = cbor2.loads(demux_result[0])
                demux_result[0] = pcap.base64ify(demux_result[0])
                demux_result[1] = pcap.base64ify(demux_result[1])
                demux_result[2] = cbor2.loads(demux_result[2])

            logging.info(f'Demultiplexed log entry:{demux_result}')

            sub_client = sub_client_dict[demux_result[2]['destination']]

            if sub_client.open_requests.__contains__(demux_result[2]['ID']):
                sub_client.open_requests.remove(demux_result[2]['ID'])

                f = feed.FEED(sub_client.isp_client_feed)
                f._append(result)
                sub_client.replicator.replicate()

                logging.info(e)
    p.close()


# following are again watchdog event functions
def on_created(event):
    # TODO init on RT
    logging.debug(f"created: {event.src_path}")


def on_deleted(event):
    logging.critical(f"deleted: {event.src_path}")


def on_modified(event):
    '''
    This is the key method of the file system polling mechanism.
    When a file in the specified directory is changed, an event gets evaluated.
    :param event: the file system event - containing the file which was changed
    :return:
    '''
    # on a feed change - incoming replication - watchdog detects it and invokes this function
    # it searches from which feed it came and procedes accordingly
    print('--------------------------------------')
    logging.debug(f"Feed update:{event.src_path}")
    logging.warning(f'File modified:{event.src_path}')
    global client_dict

    for client in client_dict.values():
        # checks if the file corresponds to a client contract
        if f'{event.src_path}' == client.client_isp_feed:
            logging.info(f'Handling client incoming')
            handle_new_requests(client)

    for sub_client in sub_client_dict.values():
        # checks if the file corresponds to a sub client contract
        if f'{event.src_path}' == sub_client.client_isp_feed:
            logging.info(f'Handling SUB client incoming')
            handle_new_sub_request(sub_client)

    for server in server_dict.values():
        # checks if the file corresponds to a server contract
        logging.debug(server.to_string())
        if f'{event.src_path}' == server.server_isp_feed:
            logging.info(f'Handling server incoming')
            server_incoming(server)


def on_moved(event):
    logging.critical(f"ok ok ok, someone moved {event.src_path} to {event.destination}")


def multiplex_request(w, sub_client: Client):
    '''
    This method takes a full log entry and multiplexes it into the content section of another
    :param w: full log entry with all information
    :param sub_client: contract which holds source feed
    :return:
    '''
    e = cbor2.loads(w)
    if e[2] != None:
        e[2] = cbor2.loads(e[2])

    server = server_dict[e[2]['destination']]

    request = w

    mux_request = {
        "introduce_ID": server.highest_introduce_ID,
        "type": 'mux',
        "source": sub_client.name,
        'destination': server.name,
        'request': request
    }
    logging.info(mux_request)

    sub_client.open_requests.append(e[2]['ID'])
    sub_client.highest_request_ID += 1
    server.highest_introduce_ID += 1
    wr_feed(server.isp_server_feed, server.isp_server_key, mux_request)
    server.replicator.replicate()


def handle_new_sub_request(sub_client: Client):
    '''
    This method is invoked if an end-to-end feed is changed.
    Since these are not directly replicated, it will be multiplexed accordingly.
    :param sub_client: contract which holds e2e feed
    :return:
    '''
    p = pcap.PCAP(sub_client.client_isp_feed)
    p.open('r')
    for w in p:

        e = cbor2.loads(w)
        href = hashlib.sha256(e[0]).digest()
        e[0] = cbor2.loads(e[0])

        e[0] = pcap.base64ify(e[0])
        fid = e[0][0]
        seq = e[0][1]
        if e[2] != None:
            e[2] = cbor2.loads(e[2])

        print(e)
        if isinstance(e[2], dict) and e[2]['type'] == 'request':
            request_ID = e[2]["ID"]

            logging.info(e)

            if request_ID > sub_client.highest_request_ID:
                multiplex_request(w, sub_client)


def handle_new_requests(client: Client):
    '''
    This is the read result and send request method combined for the client feed.
    Since the server can also send requests to the client, the feeds cannot be treated as request and result feeds.
    Needs to be overthought again.
    :param client: Contract
    :return:
    '''
    p = pcap.PCAP(client.client_isp_feed)
    p.open('r')
    for w in p:

        try:
            e = cbor2.loads(w)
        except:
            logging.critical('cbor2 loader failed - skipping logentry')
            continue
        href = hashlib.sha256(e[0]).digest()
        e[0] = cbor2.loads(e[0])

        e[0] = pcap.base64ify(e[0])
        fid = e[0][0]
        seq = e[0][1]
        if e[2] != None:
            e[2] = cbor2.loads(e[2])

        if isinstance(e[2], dict) and e[2]['type'] == 'result' and e[2]['ID'] > client.highest_request_ID:
            result = {
                'introduce_ID': e[2]['introduce_ID'],
                'type': 'result',
                'service': e[2]['service'],
                'attributes': e[2]['attributes'],
                'result': e[2]['result']
            }

            server = server_dict[e[2]['attributes']]
            wr_feed(server.isp_server_feed, server.isp_server_key, result)
            server.replicator.replicate()

        if isinstance(e[2], dict) and e[2]['type'] == 'request':
            request_ID = e[2]["ID"]

            if request_ID > client.highest_request_ID:

                read_request(e[2], client)
                # client.highest_request_ID += 1
            elif client.open_requests.__contains__(request_ID):
                # client.open_requests.remove(request_ID)
                # read_request(e[2], client)
                pass
    p.close()


def start_watchdog():
    '''
    Starts the thread for watchdog and reacts accordingly for any feed changes
    :return:
    '''
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

    path = isp_config['location']
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
    parser.add_argument('config')

    # parser.add_argument('--debug')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

    # setting up environment
    client_dict = dict()
    sub_client_dict = dict()
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

    isp_config = json.loads(open(args.config).read())
    init()
    init_clients()
    init_servers()

    for cli in client_dict.values():
        logging.info(cli.to_string())
    for ser in server_dict.values():
        logging.info(ser.to_string())
    for sub in sub_client_dict.values():
        logging.info(sub.to_string())
    start_watchdog()

    logging.info("Dumping feeds...")
    for client in client_dict.values():
        logging.info('------------------------------')
        logging.info(f'dumping feed {client.client_isp_feed}')
        logging.info('')
        pcap.dump(client.client_isp_feed)
        logging.info('------------------------------')
        logging.info(f'dumping feed {client.isp_client_feed}')
        logging.info('')
        pcap.dump(client.isp_client_feed)

    for server in server_dict.values():
        logging.info('------------------------------')
        logging.info(f'dumping feed {server.isp_server_feed}')
        logging.info('')
        pcap.dump(server.isp_server_feed)
        logging.info('------------------------------')
        logging.info(f'dumping feed {server.server_isp_feed}')
        logging.info('')
        pcap.dump(server.server_isp_feed)

    # request = handle_input(input())
