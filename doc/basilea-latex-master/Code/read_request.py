def read_request(request: dict):
    ID, service, attributes = extract(request)
    result = invoke(service=service, param=attributes)
    return request, result
