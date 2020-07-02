def read_request(request: dict):
    ID, service, attributes = extract(request) 
    result = invoke(service=service, param=attributes) #needs to be defined if service suspends this method
    return request, result # could also be send_result(request, result)
