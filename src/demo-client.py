#!/usr/bin/env python3

# demo-chat.py
# Nov 2019 <christian.tschudin@unibas.ch>
import re

import cbor2
import copy
import curses
import sys
import traceback
import watchdog.observers as wdo

import lib.feed as feed

trace = None
prog = ' client demo'

full_pattern = r'^service=([a-zA-Z ]+) destination=([a-zA-Z ]+) attrs=\[(([0-9a-zA-Z ][0-9a-zA-Z_ ]*)*([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
full_test_string = 'service=echo      destination=isp  attrs=[te  st, hallo welt, noweqfdnqw] '

short_pattern = r'^--([a-zA-Z ]+) -([a-zA-Z ]+) \[(([0-9a-zA-Z ]*[0-9a-zA-Z_ ]*)([,][0-9a-zA-Z ][0-9a-zA-Z_ ]*)*)\]'
short_test_string = '--echo      -isp  [te  st, hallo welt, noweqfdnqw]'

delimitor = '---------------------------------------------'

def test_full_regex():
    print(delimitor)
    print()
    print('TESTING FULL PATTERN')
    matchobj = re.match(full_pattern, full_test_string)
    print(bool(matchobj))
    if (matchobj):
        print(matchobj.group())
        print(matchobj.group(1))
        print(matchobj.group(2))
        print(matchobj.group(3))
        l = matchobj.group(3).split(", ")
        print(l)


def test_short_regex():
    print(delimitor)
    print()
    print('TESTING SHORT PATTERN')
    matchobj = re.match(short_pattern, short_test_string)
    print(bool(matchobj))
    if (matchobj):
        print(matchobj.group())
        print(matchobj.group(1))
        print(matchobj.group(2))
        print(matchobj.group(3))
        l = matchobj.group(3).split(", ")
        print(l)


def test_handle_post():
    print(delimitor)
    print('TESTING handle_post')
    print()
    right_full = 'service=echo destination=isp attrs=[Please echo this]'
    wrong_full = 'service=stream destination=isp attrs=None'

    right_short = '--stream -netflix [Black Mirror]'
    wrong_short = '-echo --google []'

    empty_full = 'service=empty destination=void attrs=[]'
    empty_short = '--empty -void []'

    print(f'Testing right_full: {right_full}')
    handle_input(right_full, None)
    print()
    '''
    print(f'Testing wrong_full: {wrong_full}')
    handle_post(wrong_full, None)
    print()
    '''
    print(f'Testing right_short: {right_short}')
    handle_input(right_short, None)
    print()
    '''
    print(f'Testing wrong_short: {wrong_short}')
    handle_post(wrong_short, None)
    '''
    print()
    print(f'Testing empty_full: {empty_full}')
    handle_input(empty_full, None)
    print()
    print(f'Testing empty_short: {empty_short}')
    handle_input(empty_short, None)


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

        send_request(service=service, destination=destination, attributes=attributes)
        # win.addstr(f"debugging post({msg})")
    elif matching_short:
        service = matching_short.group(1)
        destination = matching_short.group(2)
        attributes_str = matching_short.group(3)
        attributes = attributes_str.split(', ')

        print(
            f'Detected short: service:{service}, destination:{destination} with the following attributes:{attributes}')

        send_request(service=service, destination=destination, attributes=attributes)

    else:
        print('Input not matching pattern')
        # win.addstr(f"failed post({msg})")

    # win.refresh()


## service=echo destination=isp attr=[test]


def send_request(service, destination, attributes):
    # TODO: check service and dest available
    # TODO: Write to feed
    ID = 0
    log = open('../related/mini-ssb-20190906/client-mock-log.txt', 'a')

    packet = f'{ID}:request:{service}:{destination}:{attributes}\n'
    #packet_ser = core.serialize(packet)

    log.write(packet)
    #log.write(str(packet_ser) + '\n')


def read_result(ID):
    log = open('../related/mini-ssb-20190906/isp-mock-log.txt', 'r')
    lines = log.readlines()
    for line in lines:
        if (line.split(':')[0] == str(ID)) and (line.split(':')[1] == 'result'):
            result = line.split(':')
            if len(result) != 6:
                print(f'ID:{ID} -> result error')
            else:
                service = result[2]
                destination = result[3]
                attributes = result[4]
                res = result[5]
                print(f'ID:{ID} -> got result:{res} from request  service={service} destination={destination}'
                      f' with attributes={attributes}')


# ----------------------------------------------------------------------
def testing():
    print(delimitor)
    print('TESTING')
    # test_full_regex()
    # test_short_regex()
    # test_handle_post()
    write_feed_test()

def write_feed_test():
    f = 'lib/testing.pcap'
    key = 'lib/testing.key'
    msg = {}
    msg.update({'ID': 0})
    msg.update({'type': 'request'})
    feed.append_feed(f,key, msg)

if __name__ == '__main__':


    testing()
    # curses.wrapper(lambda stdscr: main(stdscr, sys.argv))
    if trace:
        print(trace)

# eof
