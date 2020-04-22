# Client Pseudo Code
Generally the Client shall run two different processes. The *service listening* process, where information can be delivered to
without the client specifically requesting any service and the *service executing* process, where the user decides, what services they want to use

####Service Executing Process
    while (alive):
        response = (bool successful, result)   # some kind of global or manager
        
        
        input = get_service(service, attrs[])  # waiting for input
        executing_process = multiprocessing.Process(target=input.service, args(input.attrs[], response))
        executeing_process.start()
        execute(executeing_process).join()  # waits for isp/server answer

        response.save()
        response.clear()
        
####Service Listening Process      
    while (alive):
        listening_process = listen_to_isp(isp)
        listening_process.start()
        listening_process.save()

The executing process cann pass arguments to premade methods which invoke isp services. E. g. 

    def echo(attrs[],  response):
        handled_attrs[] = handle_echo_related_stuff(attrs[])
        conn = rpyc.connect("0.0.0.0", 18862, config={"sync_request_timeout": 300})
        isp = conn.root
        response = isp.echo(attrs=handled_attrs[])
        return response
    
    
    def ping(attrs[],  response):
        ...
        response = isp.ping(attrs=handled_attrs[])
        return response
    
    
    def introduce_me(attrs[],  response):
        ...
        response = isp.introduce_me(attrs=handled_attrs[])
        return response
    
    
    def detruce_me(attrs[],  response):
        ...
        response = isp.detruce_me(target=detruce, attrs=handled_attrs[])
        return response
        
Like this, for every new Service available, the client has to be updated, better if the isp handles the clients service request.      
In stead of:
    
    executing_process = multiprocessing.Process(target=input.service, args(input.attrs[], response))
    
We could use something like:

    executing_process = multiprocessing.Process(target=execute, args(input.service, input.attrs[], response))
    
and 

    def execute(target, attrs[], response):
        handled_attrs[] = handle_deduction_related_stuff(attrs[])
        conn = rpyc.connect("0.0.0.0", 18861, config={"sync_request_timeout": 300})
        isp = conn.root
        response = isp.eval_service(target=target, attrs=handled_attrs[]) #is (successful, result) tupel
        return response

So most to all logic is basically managed by the ISP and the client gets merely notified about new services from the ISP
