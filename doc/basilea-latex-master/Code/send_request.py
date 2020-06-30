def send_request(destination: Feed, service: str, attributes: list):
    request = build_request(ID=get_next_ID(),type='request', service, attributes)
    destination.write(request)
    destination.replicator.replicate() #neede if write() does not replicate

    wait_for_resolution(request) #keep track of pending requests
