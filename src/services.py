import logging


def testservice(attributes):
    return 'testanswer'

def echo(attributes):
    logging.info(f'Detected service: echo')
    return attributes

def add(attributes):
    sum = 0
    if isinstance(attributes,list):
        for a in attributes:
            if isinstance(a, int):
                sum += a
            else:
                pass
        return sum
    else:

        invalid_attributes(attributes)



def invalid_attributes(attributes):
    pass