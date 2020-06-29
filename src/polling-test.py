import hashlib
import multiprocessing
import os
import sys

import cbor2

import lib.pcap as pcap
import lib.feed as feed
import lib.crypto as crypto
import lib.event
import select


def write_feed_test():
    f = 'lib/testing.pcap'
    key = 'lib/testing.key'
    msg = {}
    msg.update({'ID': 0})
    msg.update({'type': 'request'})
    feed.append_feed(f, key, msg)


def load_keyfile(fn):
    with open(fn, 'r') as f:
        key = eval(f.read())
    if key['type'] == 'ed25519':
        fid = bytes.fromhex(key['public'])
        signer = crypto.ED25519(bytes.fromhex(key['private']))
    elif key['type'] == 'hmac_sha256':
        fid = bytes.fromhex(key['feed_id'])
        signer = crypto.HMAC256(bytes.fromhex(key['private']))
    return fid, signer


def test_init():
    name = 'jannik'
    if os.path.exists(f'feeds/{name}/{name}.pcap') and os.path.exists(f'feeds/{name}/{name}.key'):
        print(f'Feed and key for {name} exist')
    else:
        key_pair = crypto.ED25519()
        key_pair.create()
        header = ("# new ED25519 key pair: ALWAYS keep the private key as a secret\n")
        keys = ('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        print("# new ED25519 key pair: ALWAYS keep the private key as a secret")
        print('{\n  ' + (',\n '.join(key_pair.as_string().split(','))[1:-1]) + '\n}')

        if not os.path.exists(f'feeds/{name}'):
            os.mkdir(f'feeds/{name}')
        f = open(f'feeds/{name}/{name}.key', 'w')
        f.write(header)
        f.write(keys)
        f.close()

        try:
            os.remove(f'feeds/{name}/{name}.pcap')
        except:
            pass

        fid, signer = load_keyfile(f'feeds/{name}/{name}.key')
        client_feed = feed.FEED(f'feeds/{name}/{name}.pcap', fid, signer, True)

        global client_log
        global client_key
        client_log = f'feeds/{name}/{name}.pcap'
        client_key = f'feeds/{name}/{name}.key'


def poll_process(poller):
    e = poller.poll()
    print('starting polling')
    while (True):
        print('here')
        for descriptor, Event in e:
            print('detected')


def polling_test():
    print('polling test')

    pcapfile = 'feeds/client01/client01.pcap'
    keyfile = 'feeds/client01/client01.key'
    p = pcap.PCAP(pcapfile)
    p.open('r')

    poller = select.poll()

    poller.register(p, select.POLLIN)

    feed.append_feed(pcapfile, keyfile, 'TEST')
    print('starting polling')
    while (True):
        print('here')
        e = poller.poll()
        for descriptor, Event in e:
            print(descriptor)
            print('detected')


def on_created(event):
    print(f"hey, {event.src_path} has been created!")


def on_deleted(event):
    print(f"what the f**k! Someone deleted {event.src_path}!")


def on_modified(event):
    print(f"hey buddy, {event.src_path} has been modified")


def on_moved(event):
    print(f"ok ok ok, someone moved {event.src_path} to {event.destination}")


def test_watchdog():
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

    path = "."
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    my_observer.start()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


def test_read_BW():
    pcapfile = 'feeds/client01/client01.pcap'
    keyfile = 'feeds/client01/client01.key'
    p = pcap.PCAP(pcapfile)
    p.open('r')

    print('hello')

    w = p.read()

    print(p.__iter__().__next__())

    for w in (p):

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
    p.close()


def test_logging(bug):
    import logging

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

    # The background is set with 40 plus the number of the color, and the foreground with 30

    # These are the sequences need to get colored ouput
    RESET_SEQ = "\033[0m"
    COLOR_SEQ = "\033[1;%dm"
    BOLD_SEQ = "\033[1m"

    def formatter_message(message, use_color=True):
        if use_color:
            message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
        else:
            message = message.replace("$RESET", "").replace("$BOLD", "")
        return message

    COLORS = {
        'WARNING': YELLOW,
        'INFO': WHITE,
        'DEBUG': BLUE,
        'CRITICAL': YELLOW,
        'ERROR': RED
    }

    class ColoredFormatter(logging.Formatter):
        def __init__(self, msg, use_color=True):
            logging.Formatter.__init__(self, msg)
            self.use_color = use_color

        def format(self, record):
            levelname = record.levelname
            if self.use_color and levelname in COLORS:
                levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
                record.levelname = levelname_color
            return logging.Formatter.format(self, record)

    class ColoredLogger(logging.Logger):
        FORMAT = "[$BOLD%(name)-20s$RESET][%(levelname)-18s]  %(message)s ($BOLD%(filename)s$RESET:%(lineno)d)"
        COLOR_FORMAT = formatter_message(FORMAT, True)

        def __init__(self, name):
            logging.Logger.__init__(self, name, logging.DEBUG)

            color_formatter = ColoredFormatter(self.COLOR_FORMAT)

            console = logging.StreamHandler()
            console.setFormatter(color_formatter)

            self.addHandler(console)
            return

    logging.setLoggerClass(ColoredLogger)

    logging.info('So should this')
    logging.warning('And this, too')
    logging.critical('lol')
    logging.debug('This message should go to the log file')


if __name__ == '__main__':




    # write_feed_test()
    # test_init()
    # polling_test()
    # test_watchdog()
    # test_read_BW()
    # test_logging(True)
    # test_logging(False)
    '''
    print(os.listdir("feeds/fff111"))

    for file in os.listdir("feeds/fff111"):
        print(os.path.isfile(os.path.join("feeds/fff111", file)))
        if os.path.isfile(os.path.join("feeds/fff111", file)) and file.endswith(".pcap"):
            print(file)

    # pcap.dump("feeds/fff111/fff111_ser001.pcap")
    # pcap.dump("feeds/fff111/ser001_fff111.pcap")
    # pcap.dump("feeds/fff111/isp001_fff111.pcap")
    pcap.dump("feeds/isp001/isp001_ser001.pcap")
    print('----------------------------------------------------------------')
    print('----------------------------------------------------------------')
    print('----------------------------------------------------------------')

    pcap.dump('feeds/ser001/ser001_fff111.pcap')
    print('----------------------------------------------------------------')
    print('----------------------------------------------------------------')
    print('----------------------------------------------------------------')

    pcap.dump('feeds/isp001/ser001_isp001.pcap')
    
    # pcap.dump("feeds/client01/isp_client01.pcap")
    

    pcap.dump("feeds/ser001/isp001_ser001.pcap")
    
    
    print("####################")
    print("####################")
    print("####################")
    print("####################")

    p = pcap.PCAP("feeds/fff111/fff111_isp001.pcap")
    p.open('r')

    fid, signer = feed.load_keyfile("feeds/fff111/fff111_isp001.key")
    print(f'fid: {pcap.base64ify(fid)}')
    print(f'signer: {pcap.base64ify(signer.sk)}')

    to_append = None
    to_write = None
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
            if e[2]['ID'] == 2:
                print(e)
                print(e[1])
                print(pcap.base64ify(e[1]))
                to_append = w
                to_write = e[2]
        print('--------------')



    print(to_append)

    fid, signer = feed.load_keyfile("lib/new.key")
    print(f'fid: {pcap.base64ify(fid)}')
    print(f'signer: {pcap.base64ify(signer.sk)}')
    f = feed.FEED("lib/new.pcap")

    print("#################################")
    other_feed = pcap.PCAP("lib/new.pcap")
    other_feed.open('r')


    #f._append(to_append)
    #f.write(to_write)



    for w in other_feed:
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
            if e[2]['ID'] == 2:

                print(pcap.base64ify(e[1]))

        print(e)
        print('--------------')

    f = feed.FEED("./feeds/ser001/fff111_ser001.pcap", create_if_notexisting=True)
    f._append(to_append)
    
    '''

    print("---------------------")
    pcap.dump("./feeds/ser001/ser001_isp001.pcap")
    print("---------------------")
    pcap.dump("./feeds/cli001/cli001_ser001.pcap")
    print("---------------------")
    pcap.dump("./feeds/isp001/isp001_ser001.pcap")

