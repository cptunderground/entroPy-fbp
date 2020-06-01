import json
import logging
import inspect
from isp import Client

class Service():
    def testservice(attributes):
        '''
        This service is just a testing service. It returns 0 on any given param.
        :param attributes: Any
        :return: 0
        '''
        return 0

    def getservers(attributes):
        '''
        :param: 'All'
        :return: every registered server key
        '''
        if str(attributes).lower() == 'all':
            conf = json.loads(open("isp-conf.json").read())

            return conf["server_keys"]
        else:
            Service.invalid_attributes('getserver', attributes, error='attribute needs to be all')

    def echo(attributes):
        '''
        :param attributes: Any
        :return: The given attributes as is
        '''
        logging.info(f'Detected service: echo')
        return attributes

    def add(attributes):
        '''
        The add service takes a list of integers and adds them together
        :param attributes: A list of integers
        :return: the sum of all integers in the list
        '''
        sum = 0
        print(attributes)
        if isinstance(attributes, list):
            for a in attributes:
                if isinstance(a, int):
                    print(a)
                    sum += a
                else:
                    pass
            return sum
        else:

            Service.invalid_attributes('add', attributes, error='unknown')

    def invalid_attributes(src, attributes, error):
        '''
        If a service is invoked with poorly chosen attributes, it passes these here and an error message gets returned.
        :param attributes: Any
        :return: Error
        '''
        return f'Error: {error} in attributes: {attributes} for service: {src}'



def servicecatalog(attributes):
    '''
    :param attributes: None
    :return: All services provided by ISP
    '''
    # TODO announce all services at init

    services = inspect.getmembers(object=Service, predicate=inspect.isfunction)
    result = []
    for service in services:
        name, f = service
        description = inspect.getdoc(eval(f'Service.{name}'))
        tuple = (name, description)
        result.append(tuple)
    return f'Service catalog: {result}'
    pass


