#!/usr/bin/env python3
import inspect
import logging
# import gevent
# from gevent import monkey
# monkey.patch_all()
import rpyc


class PingService(rpyc.Service):
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    def exposed_ping(self, message):
        if message == "Ping":
            print("received PingService - answering client")
            return True
        else:
            return "Parameter Problem"


class EchoService(rpyc.Service):
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    def exposed_echo(self, message, value):
        if message == "Echo":
            print("received EchoService - answering client")
            return "Echo Reply: " + str(value)
        else:
            return "Parameter Problem"


class TestingService(rpyc.Service):
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    def exposed_ping(self, message):
        print("received PingService - answering client")
        return True

    def exposed_echo(self, value):
        print("received EchoService - answering client")
        return "Echo Reply: " + str(value)

    def exposed_introduce_me(self, value):
        return True

    def exposed_detruce_me(self):
        return True

    def exposed_get_news(self):
        return "Today's News: Some important news."


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    choice = 'ThreadedServer'  # Debugging
    svc_server = None
    server_class = {}
    # Populate for 'ForkingServer', 'GeventServer', 'OneShotServer', 'ThreadPoolServer', and 'ThreadedServer'
    for name, value in inspect.getmembers(rpyc.utils.server, inspect.isclass):
        if rpyc.utils.server.Server in getattr(value, '__mro__', []):
            server_class[name] = value
    svc_server = server_class[choice]

    # TODO: Ask Tschudin better choice: Either opening a port for each service or handle all services in one service on one port
    testing_svc = svc_server(service=TestingService, port=18862, protocol_config={'allow_all_attrs': True})

    testing_svc.start()
