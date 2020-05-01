import argparse
import hashlib
import os

import cbor2

import lib.feed as feed
import lib.pcap as pcap
import lib.crypto as crypto
import services


def create_feed(name, peers):
    global isp_key
    global isp_log
    global next_result_ID

    if os.path.exists(f'feeds/{name}/{name}_{peers}.pcap') and os.path.exists(f'feeds/{name}/{name}_{peers}.key'):
        print(f'Feed and key for {name} exist')
        isp_key = f'feeds/{name}/{name}_{peers}.key'
        isp_log = f'feeds/{name}/{name}_{peers}.pcap'
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        print("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        print('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

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

        # TODO exchange source and dest with public keys
        feed_entry = {
            'ID': next_result_ID,
            'type': 'initiation',
            'source': 'client',
            'destination': 'client',
            'service': 'init',
            'attributes': name
        }
        next_result_ID += 1

        print(f'writing in {client_log}: {feed_entry}')
        client_feed.write(feed_entry)


def init():
    global next_result_ID
    print(isp_log)

    create_feed(args.name, args.peers)

    print('Reading Feed...')
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
        print(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
        print(f"   hashref={href.hex()}")
        print(f"   content={e[2]}")

        if isinstance(e[2], dict) and e[2]['type'] == 'result':
            print(f'ID={e[2]["ID"]}')

            next_result_ID = max(int(e[2]["ID"]), next_result_ID)

    next_result_ID += 1
    p.close()
    pass


def init_peer():
    if os.path.exists(f'feeds/{args.peers}/{args.peers}.pcap'):
        global client_log
        client_log = f'feeds/{args.peers}/{args.peers}.pcap'

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
            print(f"** fid={fid}, seq={seq}, ${len(w)} bytes")
            print(f"   hashref={href.hex()}")
            print(f"   content={e[2]}")

            if isinstance(e[2], dict) and e[2]['type'] == 'request':
                request_ID = e[2]["ID"]
                print(f'ID={e[2]["ID"]}')

                if request_ID > next_result_ID:
                    read_request(e[2])

        p.close()
        pass
    else:
        pass


def send_result(log_entry, result):
    feed_entry = {
        'ID': log_entry['ID'],
        'type': 'result',
        'source': args.name,
        'destination': log_entry['source'],
        'service': log_entry['service'],
        'result': result
    }

    print(f'writing in {isp_log}: {feed_entry}')
    wr_feed(isp_log, isp_key, feed_entry)


def wr_feed(f, key, msg):
    feed.append_feed(f, key, msg)


def send_invalid_result(log_entry, error):
    send_result(log_entry, f'Invalid request - source:{error}')


def invalid_format(log_entry):
    print("INVALID LOG ENTRY")
    print(log_entry)
    send_invalid_result(log_entry, 'format')


def invalid_service(log_entry):
    print("INVALID SERVICE")
    print(log_entry)
    send_invalid_result(log_entry, 'service')


def read_request(log_entry: dict):
    print(log_entry['ID'])
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
    try:
        f = eval(f'services.{log_entry["service"]}')
        result = f(log_entry['attributes'])
        send_result(log_entry, result)
    except:
        invalid_service(log_entry)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-ISP for FBP')
    # parser.add_argument('--keyfile')
    # parser.add_argument('pcapfile', metavar='PCAPFILE')
    parser.add_argument('name')
    parser.add_argument('peers')  # TODO LIST

    args = parser.parse_args()
    next_result_ID = 0
    isp_log = 'unknown'
    isp_key = 'unknown'

    client_log = 'unknown'

    init()
    init_peer()


    print("dumping feed...")
    pcap.dump(isp_log)
    # request = handle_input(input())
