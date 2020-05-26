import hashlib
import logging
import os
import re
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import cbor2

from lib import pcap, crypto, feed


class cServer():
    def __init__(self, name: str, s_c_feed: str, c_s_feed: str, c_s_key: str,
                 highest_introduce_ID: int,
                 open_introduces: list):
        self.name = name
        self.s_c_feed = s_c_feed
        self.c_s_feed = c_s_feed
        self.c_s_key = c_s_key
        self.highest_introduce_ID = highest_introduce_ID
        self.open_introduces = open_introduces


class FBP_Client:
    def __init__(self, name, c_i_log, c_i_key, i_c_log):
        self.name = name
        self.next_request_ID = 0
        self.highest_result_ID = 0
        self.result_ID_list = []
        self.c_i_log = c_i_log
        self.c_i_key = c_i_key

        self.i_c_log = i_c_log  # replication of the i_c_log in ISP

        self.c_server_dict = dict()

    def create_feed(self):

        if os.path.exists(self.c_i_log) and os.path.exists(
                self.c_i_key):
            logging.info(f'Feed and key for exist')

        else:
            key_pair = crypto.ED25519()
            key_pair.create()
            header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
            keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            logging.info("# new ED25519 key pair: ALWAYS keep the private key as a secret")
            logging.info('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

            if not os.path.exists(f'feeds/{self.name}'):
                os.mkdir(f'feeds/{self.name}')
            f = open(self.c_i_key, 'w')
            f.write(header)
            f.write(keys)
            f.close()

            try:
                os.remove(self.c_i_log)
            except:
                pass

            fid, signer = feed.load_keyfile(self.c_i_key)
            client_feed = feed.FEED(self.c_i_log, fid, signer, True)

            # TODO exchange source and dest with public keys
            feed_entry = {
                'ID': self.next_request_ID,
                'type': 'initiation',
                'source': self.name,
                'destination': 'TODO',
                'service': 'init',
                'attributes': None
            }
            self.next_request_ID += 1
            client_feed.write(feed_entry)

    def init(self):

        self.create_feed()

        logging.info('Initialising from feeds...')
        p = pcap.PCAP(self.c_i_log)
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
                logging.debug(f'from init request  ID={e[2]["ID"]}')
                self.result_ID_list.append(e[2]['ID'])
                self.next_request_ID = max(int(e[2]["ID"]), self.next_request_ID)

        p.close()

        p = pcap.PCAP(self.i_c_log)
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
                if self.result_ID_list.__contains__(e[2]['ID']):
                    self.read_result(e[2]['ID'])

        p.close()

        for s in self.c_server_dict.values():
            p = pcap.PCAP(s.c_s_feed)
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
                    logging.debug(f'from init request  ID={e[2]["ID"]}')
                    self.result_ID_list.append(e[2]['ID'])
                    self.next_request_ID = max(int(e[2]["ID"]), self.next_request_ID)

            p.close()

        self.next_request_ID += 1

    def handle_result(self, log_entry):
        if log_entry['service'] == 'introduce':
            logging.info(f'Got introduce result from ID:{log_entry["ID"]}')
            logging.info(f'-> {log_entry}')

            if log_entry['result'] != 'already exists':
                self.create_E2E_feed(log_entry['result'])
                self.setup_server(log_entry)
        else:
            logging.info(f'got result:{log_entry["result"]} from ID:{log_entry["ID"]} -> {log_entry}')
            logging.info(f'-> {log_entry}')

    def handle_new_results(self):
        for result_ID in self.result_ID_list:
            self.read_result(result_ID)

    def read_result(self, ID):

        p = pcap.PCAP(self.i_c_log)
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
                if e[2]['ID'] == ID:
                    logging.debug(f'from read_result  ID={e[2]["ID"]}')
                    logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
                    logging.debug(f"   hashref={href.hex()}")
                    logging.debug(f"   content={e[2]}")

                    if self.result_ID_list.__contains__(ID):
                        self.result_ID_list.remove(ID)
                    self.handle_result(e[2])
                    return True

        p.close()
        return False


    def on_created(self, event):
        logging.debug(f"Created: {event.src_path}")

    def on_deleted(self, event):
        logging.critical(f"Deleted: {event.src_path}!")

    def on_modified(self, event):
        global c_server_dict
        logging.debug(f"Modified: {event.src_path}")
        if f'{event.src_path[2:]}' == self.i_c_log:
            self.handle_new_results()
        else:
            print(f'{event.src_path[2:]}')
            for s in self.c_server_dict.values():
                if s.s_c_feed == f'{event.src_path[2:]}':
                    print('for works')
                    self.handle_new_s_results(s)
            # s = c_server_dict[f'{event.src_path[2:]}']
            # handle_new_s_results(s)

    def on_moved(self, event):
        logging.critical(f"Moved: {event.src_path} to {event.dest_path}")

    def start(self, method_to_call):
        patterns = "*"
        ignore_patterns = ""
        ignore_directories = True
        case_sensitive = True
        my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)

        my_event_handler.on_created = self.on_created
        my_event_handler.on_deleted = self.on_deleted
        my_event_handler.on_modified = self.on_modified
        my_event_handler.on_moved = self.on_moved

        path = "./feeds"
        go_recursively = True
        my_observer = Observer()
        my_observer.schedule(my_event_handler, path, recursive=go_recursively)

        my_observer.start()
        try:
            while True:
                method_to_call()
                # time.sleep(1)
                logging.info('next imput:')
        except KeyboardInterrupt:
            my_observer.stop()
            my_observer.join()

    def send_request(self, request: dict):

        # TODO exchange sourece and dest with public keys

        feed_entry = {
            'ID': self.next_request_ID,
            'type': 'request',
            'source': self.name,
            'destination': request['destination'],
            'service': request['service'],
            'attributes': request['attributes']
        }

        if str(request['destination']).lower() == 'isp':
            self.wr_feed(self.c_i_log, self.c_i_key, feed_entry)
            self.result_ID_list.append(feed_entry['ID'])
            self.next_request_ID += 1
        else:
            # TODO optimize
            if len(c_server_dict) != 0:
                for server in c_server_dict.values():
                    if str(request['destination']).lower() == server.name:
                        self.wr_feed(server.c_s_feed, server.c_s_key, feed_entry)
                        self.result_ID_list.append(feed_entry['ID'])
                        self.next_request_ID += 1
                    else:
                        logging.warning(f'No server registered for {request["destination"]}, try to introduce first')
            else:
                logging.info('No servers registered')

    def wr_feed(self, f, key, msg):
        logging.info(f'Writing in {f}: {msg}')
        feed.append_feed(f, key, msg)

if __name__ == '__main__':

    full_pattern = r'^service=([a-zA-Z ]+) destination=([a-zA-Z ]+) attrs=\[(([0-9a-zA-Z ][0-9a-zA-Z_ ]*)*([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
    full_test_string = 'service=echo      destination=isp  attrs=[te  st, hallo welt, noweqfdnqw] '

    short_pattern = r'^--([a-zA-Z ]+) -([a-zA-Z ]+) \[(([0-9a-zA-Z ]*[0-9a-zA-Z_\' ]*)([,][0-9a-zA-Z ][0-9a-zA-Z_\' ]*)*)\]'
    short_test_string = '--echo      -isp  [te  st, hallo welt, noweqfdnqw]'

    delimitor = '---------------------------------------------'


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
                'attributes': (attributes)
            }

            return request
        else:
            if msg.lower() == 'refresh':
                logging.info('Refreshing')
                c.refresh()
            else:
                logging.warning('Input not matching pattern')
            # win.addstr(f"failed post({msg})")


    def inp():
        inp = input()
        request = handle_input(inp)
        if request != None:
            c.send_request(request)
        else:
            print('')


    n = 'client'
    cil = 'feeds/client/client_isp.pcap'
    cik = 'feeds/client/client_isp.key'
    icl = 'feeds/isp/isp_client.pcap'
    logging.basicConfig(level=logging.DEBUG)
    c = FBP_Client(name=n, c_i_log=cil, c_i_key=cik, i_c_log=icl)
    c.init()
    c.start(inp)
