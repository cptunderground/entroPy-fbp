#!/usr/bin/env python3
import multiprocessing
import time
import signal
from multiprocessing import Pool, Queue, Event
import pdb  # noqa
import rpyc


def echo(main_queue, main_event, value, return_list):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
            fileno = conn.fileno()
            response = conn.root.echo("Echo", value)
            return_list.append(response)
            print("from echo " + str(return_list))

            conn.close()
    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))




def echo_forever(main_queue, main_event):
    # sys.stdout = open(os.devnull, 'w')
    try:
        count = 0
        start = time.time()
        delta = 0
        cdelta = 0
        _max = {'delta': 0, 'cdelta': 0}
        fileno = "unknown"
        addr, port = "unknown", "unknown"
        while main_event.is_set():
            count += 1
            start = time.time()
            conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
            cdelta = time.time() - start
            addr, port = conn._channel.stream.sock.getsockname()
            fileno = conn.fileno()
            start = time.time()
            response = conn.root.echo("Echo")
            print(response)
            delta = time.time() - start
            conn.close()
            _max['delta'] = delta
            _max['cdelta'] = cdelta
    except KeyboardInterrupt:
        if main_event.is_set():
            main_event.clear()
    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2} over {3}s".format(addr, port, fileno, cdelta + delta))
    finally:
        main_queue.put(_max)

def main():
    manager = multiprocessing.Manager()
    return_list = manager.list()
    sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
    pool = Pool(processes=1)
    signal.signal(signal.SIGINT, sigint)
    value = 'test'
    res = []
    main_queue = Queue()
    main_event = Event()
    main_event.set()
    proc = pool.Process(target=echo, args=(main_queue, main_event, value, return_list))
    proc.daemon = True
    proc.start()
    proc.join()
    print("from main: " + str(return_list))

def main_forever():
    try:
        print("starting")
        limit = 1
        sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = Pool(processes=limit)
        signal.signal(signal.SIGINT, sigint)
        eid_proc = {}
        main_queue = Queue()
        main_event = Event()
        main_event.set()
        for eid in range(limit):
            proc = pool.Process(target=echo_forever, args=(main_queue, main_event))
            proc.daemon = True
            proc.start()
            eid_proc[eid] = proc
            print(eid, eid_proc)
        while True:
            alive = len([_proc for _proc in eid_proc.values() if _proc.is_alive()])
            print('{0}/{1} alive'.format(alive, limit))
            if alive == 0:
                print('All of the client processes are dead. Exiting loop...')
                break
            else:
                time.sleep(1)
    except (KeyboardInterrupt, Exception):
        main_event.clear()
        for proc in eid_proc.values():
            proc.terminate()
    finally:
        res = []
        while not main_queue.empty():
            res.append(main_queue.get())
        cdelta = [_max['cdelta'] for _max in res]
        delta = [_max['delta'] for _max in res]
        if cdelta:
            cdelta = max(cdelta)
        else:
            cdelta = "unknown"
        if delta:
            delta = max(delta)
        else:
            delta = "unknown"
        time.sleep(1)
        print("Max time to establish: {0}".format(cdelta))
        print("Max time   echo reply: {0}".format(delta))
        print(cdelta, delta)


if __name__ == "__main__":
    main()
