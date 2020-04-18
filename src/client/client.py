#!/usr/bin/env python3
import multiprocessing
import time
import signal
from multiprocessing import Pool, Queue, Event
import pdb  # noqa
import rpyc
import curses


def echo(main_queue, main_event, value, return_list):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
            fileno = conn.fileno()
            response = conn.root.echo("Echo", value)
            return_list.append(response)
            conn.close()
    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))


def ping(main_queue, main_event, value, return_list):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
            fileno = conn.fileno()
            response = conn.root.ping("Ping")
            return_list.append(response)
            conn.close()
    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))

def main(command, value):
    manager = multiprocessing.Manager()
    return_list = manager.list()

    pool = Pool(processes=1)

    value = 'test' + str(command)
    main_queue = Queue()
    main_event = Event()
    main_event.set()
    proc = pool.Process(target=eval(command), args=(main_queue, main_event, value, return_list))
    proc.daemon = True
    proc.start()
    proc.join()
    print("from main: " + str(return_list))



if __name__ == "__main__":

    while (True):
        command = input()
        p = multiprocessing.Process(main(command, "testetst"))
        p.start()
        p.join()
    '''
    for i in range(5):
        main(i)
    '''