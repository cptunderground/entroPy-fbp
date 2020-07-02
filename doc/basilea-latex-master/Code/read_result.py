def read_result():
    response = feed.listen() #either the method waits for feed change or it is invoked on feed change
    ID, result = extract(response)
    return ID, result #ID is needed to map the result to the request