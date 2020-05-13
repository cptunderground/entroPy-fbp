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


#TODO adapt regex for any python structur
full_pattern = r'^service=([a-zA-Z ]+) destination=([a-zA-Z ]+) attrs=\[(([0-9a-zA-Z ][0-9a-zA-Z_ ]*)*([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
full_test_string = 'service=echo      destination=isp  attrs=[te  st, hallo welt, noweqfdnqw] '

short_pattern = r'^--([a-zA-Z ]+) -([a-zA-Z ]+) \[(([0-9a-zA-Z ]*[0-9a-zA-Z_\' ]*)([,][0-9a-zA-Z ][0-9a-zA-Z_\' ]*)*)\]'
short_test_string = '--echo      -isp  [te  st, hallo welt, noweqfdnqw]'

delimitor = '---------------------------------------------'


def handle_input(msg):
    if not isinstance(msg, str):
        msg = str(msg.decode('utf8'))
    print(f'msg: {msg}')

    matching_full = re.match(full_pattern, msg)
    matching_short = re.match(short_pattern, msg)

    # TODO eval attributes to python structure
    if matching_full:
        service = matching_full.group(1)
        destination = matching_full.group(2)
        attributes_str = matching_full.group(3)
        attributes = attributes_str.split(', ')

        print(f'Detected full: service:{service}, destination:{destination} with the following attributes:{attributes}')

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

        print(
            f'Detected short: service:{service}, destination:{destination} with the following attributes:{attributes}')

        request = {
            'service': service,
            'destination': destination,
            'attributes': (attributes)
        }

        return request
    else:
        print('Input not matching pattern')
        # win.addstr(f"failed post({msg})")


def send_request(request: dict):
    global next_request_ID
    global client_log
    global client_key
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

    print(f'writing in {client_log}: {feed_entry}')
    wr_feed(client_log, client_key, feed_entry)
    await_result(feed_entry['ID'])


def await_result(ID):
    global result_ID_list
    result_ID_list.append(ID)

def clear_await(ID):
    global result_ID_list
    result_ID_list.remove(ID)

def wr_feed(f, key, msg):
    feed.append_feed(f, key, msg)

def create_E2E_feed(identifier):
    identifier = f'feeds/{args.name}/{identifier}'

    if os.path.exists(f'{identifier}.pcap') and os.path.exists(f'{identifier}.key'):
        print(f'Feed and key for {identifier} exist')
        # TODO safe all introduced servers

    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        print("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        print('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'feeds/{args.name}'):
            os.mkdir(f'feeds/{args.name}')
        f = open(f'{identifier}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'{identifier}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'{identifier}.key')
        E2E_feed = feed.FEED(f'{identifier}.pcap', fid, signer, True)


        # TODO exchange sourece and dest with public keys
        feed_entry = {
            'ID': next_request_ID,
            'type': 'initiation',
            'source': args.name,
            'destination': args.name,
            'service': 'init',
            'attributes': 'E2E'
        }

        print(f'writing in {identifier}: {feed_entry}')
        E2E_feed.write(feed_entry)

def create_feed(name):
    global client_log
    global client_key
    global next_request_ID

    if os.path.exists(f'feeds/{name}/{name}_{args.peer}.pcap') and os.path.exists(f'feeds/{name}/{name}_{args.peer}.key'):
        print(f'Feed and key for {name} exist')
        client_key = f'feeds/{name}/{name}_{args.peer}.key'
        client_log = f'feeds/{name}/{name}_{args.peer}.pcap'
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        print("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        print('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

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

        print(f'writing in {client_log}: {feed_entry}')
        client_feed.write(feed_entry)



def init():
    global next_request_ID
    global highest_result_ID
    global result_ID_list

    print(client_log)

    create_feed(args.name)

    print('Reading Feed...')
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
        #print(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
        #print(f"   hashref={href.hex()}")
        #print(f"   content={e[2]}")

        if isinstance(e[2], dict) and e[2]['type'] == 'request':
            logging.debug(f'from init request  ID={e[2]["ID"]}')
            await_result(e[2]['ID'])
            next_request_ID = max(int(e[2]["ID"]),next_request_ID)

    next_request_ID += 1
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
    if log_entry['service'] == 'introduce':
        print('WORKED')
        print('WORKED')
        print('WORKED')
        logging.info(f'-> {log_entry}')
        print('WORKED')
        print('WORKED')
        print('WORKED')
        if log_entry['result'] != 'already exists':
            create_E2E_feed(log_entry['result'])

    else:
        logging.info(f'got result:{log_entry["result"]} from ID:{log_entry["ID"]} -> {log_entry}')
        logging.info(f'-> {log_entry}')

def handle_new_results():
    logging.info('Handle new results')
    global result_ID_list
    for result_ID in result_ID_list:
        read_result(result_ID)

def on_created(event):
    logging.info(f"hey, {event.src_path} has been created!")

def on_deleted(event):
    logging.info(f"what the f**k! Someone deleted {event.src_path}!")

def on_modified(event):
    logging.info(f"hey buddy, {event.src_path} has been modified")
    if f'{event.src_path[2:]}' == isp_log:
        handle_new_results()

def on_moved(event):
    logging.info(f"ok ok ok, someone moved {event.src_path} to {event.dest_path}")

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
            inp = input()
            request = handle_input(inp)
            if request != None:
                send_request(request)
            else:
                print('')
            time.sleep(1)
            logging.info('next imput:')
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-Client for FBP')
    #parser.add_argument('--keyfile')
    #parser.add_argument('pcapfile', metavar='PCAPFILE')
    parser.add_argument('name')
    parser.add_argument('peer')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)


    next_request_ID = 0
    highest_result_ID = 0
    result_ID_list = []
    client_log = 'unknown'
    client_key = 'unknown'

    isp_log = f'feeds/{args.peer}/{args.peer}_{args.name}.pcap' #


    init()

    logging.info("Type Request {--service -destination [attributes]}")

    request = {}



    #request = handle_input(input())
    line_in = []
    line_in.append('--echo -isp [The echo]')
    line_in.append('--echo -isp [An, echo, list]')
    line_in.append('--testservice -something [does not matter]')
    line_in.append('nothing right')
    line_in.append('--stream -netflix [Black Mirror]')

    start_watchdog()

    '''while True:
        inp = input()
        request = handle_input(line)
        if request != None:
            send_request(request)
        else:
            print('')'''


    logging.info('dumping feed...')
    pcap.dump(client_log)

# TODO: Refactor
# TODO: Logging




