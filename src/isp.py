import argparse
import hashlib
import os

import cbor2

import lib.feed as feed
import lib.pcap as pcap
import lib.crypto as crypto
import services

import logging


def create_feed(name, peers):
    global isp_key
    global isp_log
    global next_result_ID

    if os.path.exists(f'feeds/{name}/{name}_{peers}.pcap') and os.path.exists(f'feeds/{name}/{name}_{peers}.key'):
        logging.info(f'Feed and key for {name} exist')
        isp_key = f'feeds/{name}/{name}_{peers}.key'
        isp_log = f'feeds/{name}/{name}_{peers}.pcap'
        logging.info(f'ISP-LOG:{isp_log}')
        logging.info(f'ISP-KEY:{isp_key}')

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
        f = open(f'feeds/{name}/{name}_{peers}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'feeds/{name}/{name}_{peers}.pcap')
        except:
            pass

        fid, signer = feed.load_keyfile(f'feeds/{name}/{name}_{peers}.key')
        client_feed = feed.FEED(f'feeds/{name}/{name}_{peers}.pcap', fid, signer, True)

        isp_log = f'feeds/{name}/{name}_{peers}.pcap'
        isp_key = f'feeds/{name}/{name}_{peers}.key'

        logging.info(f'Created Feed for {name} in {isp_log}')
        logging.info(f'Created Key for {name} in {isp_key}')

        # TODO exchange source and dest with public keys
        feed_entry = {
            'ID': next_result_ID,
            'type': 'initiation',
            'source': name,
            'destination': name,
            'service': 'init',
            'attributes': None
        }
        next_result_ID += 1

        logging.info(f'Writing in {isp_log}: {feed_entry}')
        client_feed.write(feed_entry)


def init():
    global next_result_ID
    global result_ID_list

    create_feed(args.name, args.peers)

    logging.info('Building from feed...')
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
            logging.debug(f'ID={e[2]["ID"]}')
            logging.debug(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            logging.debug(f"   hashref={href.hex()}")
            logging.debug(f"   content={e[2]}")

            await_result(e[2]['ID'])
            next_result_ID = max(int(e[2]["ID"]), next_result_ID)

    p.close()
    pass


def init_peer():
    global next_request_ID
    if os.path.exists(f'feeds/{args.peers}/{args.peers}.pcap'):
        global client_log
        client_log = f'feeds/{args.peers}/{args.peers}.pcap'

        logging.info(f'Feed for {args.peers} exists')
        logging.info(f'Client-LOG:{client_log}')

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

                if request_ID > next_result_ID or not result_ID_list.__contains__(e[2]['ID']):
                    read_request(e[2])
                    await_result(e[2]['ID'])
                next_request_ID += 1

        p.close()
        pass
    else:
        logging.critical(f'Feed for client does not exist')

        pass


def send_result(log_entry, result):
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
    logging.info(f'Writing in {isp_log}: {feed_entry}')
    wr_feed(isp_log, isp_key, feed_entry)
    next_result_ID += 1

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


def send_invalid_result(log_entry, error):
    send_result(log_entry, f'Invalid request - source:{error}')


def invalid_format(log_entry):
    logging.warning("INVALID LOG ENTRY")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'format')


def invalid_service(log_entry):
    logging.warning("INVALID SERVICE")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'service')

def invalid_destination(log_entry):
    logging.warning("INVALID DESTINATION")
    logging.debug(log_entry)
    send_invalid_result(log_entry, 'destination')

def read_request(log_entry: dict):
    logging.info(log_entry['ID'])
    if log_entry['ID'] == None:
        invalid_format(log_entry)
    elif log_entry['type'] == None:
        invalid_format(log_entry)
    elif log_entry['source'] == None:
        invalid_format(log_entry)
    elif log_entry['destination'] == None:
        invalid_format(log_entry)
    elif log_entry['service'] == None:
        invalid_format(log_entry)
    else:
        handle_request(log_entry)


def handle_request(log_entry):
    # TODO dynamic switching over destination

    try:
        logging.info(f'Evaluating service')
        f = eval(f'services.{log_entry["service"]}')
        result = f(log_entry['attributes'])
        send_result(log_entry, result)
    except:
        invalid_service(log_entry)

def on_created(event):
    logging.info(f"hey, {event.src_path} has been created!")

def on_deleted(event):
    logging.critical(f"what the f**k! Someone deleted {event.src_path}!")

def on_modified(event):
    # TODO Regex to check if it is feed file and then handle over feed file
    logging.info(f"Feed update:{event.src_path}")
    if f'{event.src_path[2:]}' == client_log:
        logging.info(f'Handling client incoming')
        handle_new_requests(client_log)
    if f'{event.src_path[2:]}' == server_log:
        logging.info(f'Handling server incoming')
        handle_new_requests(server_log)

def on_moved(event):
    logging.critical(f"ok ok ok, someone moved {event.src_path} to {event.dest_path}")

def handle_new_requests(log):
    p = pcap.PCAP(log)
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
            if request_ID > next_result_ID:
                read_request(e[2])

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
            time.sleep(10)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-ISP for FBP')
    # parser.add_argument('--keyfile')
    # parser.add_argument('pcapfile', metavar='PCAPFILE')
    parser.add_argument('name')
    parser.add_argument('peers')  # TODO LIST
    #parser.add_argument('--debug')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

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
    init_peer()




    start_watchdog()

    print("dumping feed...")
    pcap.dump(isp_log)
    # request = handle_input(input())

# TODO: Refactor
# TODO: Logging
