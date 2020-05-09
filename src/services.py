import logging
import inspect
from isp import Client

class Service():
    def testservice(attributes):
        return 'testanswer'

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

            Service.invalid_attributes(attributes)

    def invalid_attributes(attributes):
        pass

    def announce_all_services():
        print(locals())
        print(eval('dir()'))

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


