#!/usr/bin/env python3
import inspect
import logging
import multiprocessing
import signal
import socket
from multiprocessing import Pool, Queue, Event
# import gevent
# from gevent import monkey
# monkey.patch_all()
import rpyc

def echo(main_queue, main_event, value, res):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
            fileno = conn.fileno()
            response = conn.root.echo(value)
            res.append(response)
            conn.close()
            print('from echo: ' + str(res))

    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))

def ping(main_queue, main_event, value, res):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
            fileno = conn.fileno()
            response = conn.root.ping(value)
            res.append(response)
            conn.close()
            print('from echo: ' + str(res))

    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))

def introduce_me(main_queue, main_event, value, res):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
            fileno = conn.fileno()
            response = conn.root.introduce_me(value)
            res.append(response)
            conn.close()
            print('from echo: ' + str(res))

    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))


class EchoService(rpyc.Service):
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    def exposed_eval_service(self, command, attributes):
        manager = multiprocessing.Manager()
        return_list = manager.list()

        print("received eval_service  - forwarding to executing server")

        main_queue = Queue()
        main_event = Event()
        main_event.set()
        proc = multiprocessing.Process(target=eval(command), args=(main_queue, main_event, value, return_list))
        proc.daemon = True

        proc.start()
        proc.join()
        print(return_list)
        return str(return_list[0])

    def exposed_echo(self, message, value):
        manager = multiprocessing.Manager()
        return_list = manager.list()
        if message == "Echo":
            print("received EchoService - forwarding to executing server")
            #sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
            pool = Pool(processes=1)
            #signal.signal(signal.SIGINT, sigint)
            server_res = []
            main_queue = Queue()
            main_event = Event()
            main_event.set()
            proc = pool.Process(target=echo, args=(main_queue, main_event, value, return_list))
            proc.daemon = True

            proc.start()
            proc.join()
            print(return_list)
            return str(return_list[0])
        else:
            return "Parameter Problem"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    choice = 'ThreadedServer'  # Debugging
    svc_isp = None
    isp_class = {}
    # Populate for 'ForkingServer', 'GeventServer', 'OneShotServer', 'ThreadPoolServer', and 'ThreadedServer'
    for name, value in inspect.getmembers(rpyc.utils.server, inspect.isclass):
        if rpyc.utils.server.Server in getattr(value, '__mro__', []):
            isp_class[name] = value
    svc_isp = isp_class[choice]
    echo_svc = svc_isp(service=EchoService, port=18861, protocol_config={'allow_all_attrs': True})
    echo_svc.start()