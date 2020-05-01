import multiprocessing

import lib.pcap as pcap
import lib.feed as feed
import lib.event
import select
def poll_process(poller):
    e = poller.poll()
    print('starting polling')
    while (True):
        print('here')
        for descriptor, Event in e:
            print('detected')


def polling_test():
    print('polling test')

    pcapfile = 'lib/alice.pcap'
    p = pcap.PCAP(pcapfile)
    p.open('r')

    poller = select.poll()

    e = poller.poll()
    print('starting polling')
    while (True):
        print('here')
        for descriptor, Event in e:
            print('detected')

def write_feed_test():
    f = 'lib/testing.pcap'
    key = 'lib/testing.key'
    msg = {}
    msg.update({'ID': 0})
    msg.update({'type': 'request'})
    feed.append_feed(f,key, msg)

if __name__ == '__main__':
    write_feed_test()