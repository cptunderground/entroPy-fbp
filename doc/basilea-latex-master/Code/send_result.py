def send_result(request:dict, result):
    result = build_result(ID=request['ID'], type='result', result=result)
    destination = request.get_source()
    destination.write(result)
    destination.replicator.replicate()