import hashlib
import re
import argparse
import os
import sys

import cbor2

import lib.feed as feed
import lib.pcap as pcap

full_pattern = r'^service=([a-zA-Z ]+) destination=([a-zA-Z ]+) attrs=\[(([0-9a-zA-Z ][0-9a-zA-Z_ ]*)*([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
full_test_string = 'service=echo      destination=isp  attrs=[te  st, hallo welt, noweqfdnqw] '

short_pattern = r'^--([a-zA-Z ]+) -([a-zA-Z ]+) \[(([0-9a-zA-Z ]*[0-9a-zA-Z_ ]*)([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
short_test_string = '--echo      -isp  [te  st, hallo welt, noweqfdnqw]'

delimitor = '---------------------------------------------'


def handle_input(msg):
    if not isinstance(msg, str):
        msg = str(msg.decode('utf8'))
    print(f'msg: {msg}')

    matching_full = re.match(full_pattern, msg)
    matching_short = re.match(short_pattern, msg)

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
        attributes = attributes_str.split(', ')

        print(
            f'Detected short: service:{service}, destination:{destination} with the following attributes:{attributes}')

        request = {
            'service': service,
            'destination': destination,
            'attributes': attributes
        }

        return request
    else:
        print('Input not matching pattern')
        # win.addstr(f"failed post({msg})")


def send_request(request: dict):
    global next_request_ID

    # TODO exchange sourece and dest with public keys
    feed_entry = {
        'ID': next_request_ID,
        'type': 'request',
        'source': 'client',
        'destination': request['destination'],
        'service': request['service'],
        'attributes': request['attributes']
    }
    next_request_ID += 1

    print(f'writing in {args.pcapfile}: {feed_entry}')
    wr_feed(args.pcapfile, args.keyfile, feed_entry)


def wr_feed(f, key, msg):
    feed.append_feed(f, key, msg)

def init():
    global next_request_ID

    print('Reading Feed...')
    p = pcap.PCAP(args.pcapfile)
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
            print(f'ID={e[2]["ID"]}')

            next_request_ID = max(e[2]["ID"],next_request_ID)

    next_request_ID += 1
    p.close()
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demo-Client for FBP')
    parser.add_argument('--keyfile')
    parser.add_argument('pcapfile', metavar='PCAPFILE')

    args = parser.parse_args()
    next_request_ID = 0

    init()

    print("Type Request {--service -destination [attributes]}")

    request = {}



    #request = handle_input(input())
    input = '--testservice -testdestination [testattributes]'
    request = handle_input(input)
    if request != None:
        send_request(request)
    else:
        print('')
