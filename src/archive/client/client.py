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


def extract_command(line_in):
    line_in = str(line_in)
    line_in = line_in.strip()
    if (line_in.startswith("--")):
        line_in = line_in.strip("-")
        command = line_in.split(" ")[0]
        values = line_in[line_in.index(" ") + 1:].split(" ")
        print(command)
        print(values)
        return command, values

    else:
        print("invalid command")

def evaluate_command(command, attributes):
    manager = multiprocessing.Manager()
    return_list = manager.list()

    pool = Pool(processes=1)

    main_queue = Queue()
    main_event = Event()
    main_event.set()
    proc = pool.Process(target=handle_service, args=(main_queue, main_event, command, attributes, return_list))
    proc.daemon = True
    proc.start()
    proc.join()
    print("from main: " + str(return_list))

def handle_service(main_queue, main_event, command, attributes, return_list):
    try:
        if (main_event.is_set()):
            fileno = "unknown"
            addr, port = "unknown", "unknown"
            conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
            fileno = conn.fileno()

            #execute = eval("conn.root." + command)
            #response = execute(attributes)

            response = conn.root.eval_service(command, attributes)


            return_list.append(response)
            conn.close()
    except Exception:
        import traceback
        traceback.print_exc()
        print("EXCEPT ('{0}', {1}) with fd {2}".format(addr, port, fileno))

def test():
    p = multiprocessing.Process(evaluate_command('echo', "testetst"))
    p.start()
    p.join()
    p = multiprocessing.Process(evaluate_command('ping', "3"))
    p.start()
    p.join()
    p = multiprocessing.Process(evaluate_command('introduce_me', "testetst"))
    p.start()
    p.join()


def run():
    while (True):
        line_in = input()
        command, values = extract_command(line_in)
        print(command)
        p = multiprocessing.Process(main(command, "testetst"))
        p.start()
        p.join()


if __name__ == "__main__":
    print("###################################")
    print("Usable commands:")
    print("--echo string: value")
    print("--ping int: iterations")
    print("--introduce_me bool: True, False")
    print("###################################")

    test()

