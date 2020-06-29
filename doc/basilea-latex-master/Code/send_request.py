def send_request(ID, Node, service, attributes):
    request = build_request(ID, service, attributes)
    write(Node.request_feed, request)
    Node.replicator.replicate()
