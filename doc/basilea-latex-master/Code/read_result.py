def read_result():
    response = feed.listen()
    ID, result = extract(response)
    return ID, result