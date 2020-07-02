def send_result(request:dict, result):
    result = build_result(ID=request['ID'], type='result', result=result) #builds the result accordingly
    destination = request.get_source() #since we always talked about feed pairs they need to be linked somehow
    destination.write(result)
    destination.replicator.replicate() #again needed if write() does not replicate