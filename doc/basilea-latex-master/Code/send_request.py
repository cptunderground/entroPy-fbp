def send_request(destination: Feed, service: str, attributes: list):
    request = build_request(ID=get_next_ID(),type='request', service, attributes) #builds the request accordingly
    destination.write(request)
    destination.replicator.replicate() #neede if write() does not replicate

    wait_for_resolution(request) #keep track of pending requests either by just saving the ID or suspend the system until received
