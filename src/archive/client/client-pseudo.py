# services
# first
def echo(attrs[],  response):
    handled_attrs[] = handle_echo_related_stuff(attrs[])
    response = isp.echo(attrs=handled_attrs[])
    return response


def ping(attrs[],  response):
    handled_attrs[] = handle_ping_related_stuff(attrs[])
    response = isp.ping(attrs=handled_attrs[])
    return response


def introduce_me(attrs[],  response):
    handled_attrs[] = handle_introduction_related_stuff(attrs[])
    response = isp.introduce_me(attrs=handled_attrs[])
    return response


def detruce_me(attrs[],  response):
    handled_attrs[] = handle_deduction_related_stuff(attrs[])
    response = isp.detruce_me(target=detruce, attrs=handled_attrs[])
    return response


# better
def execute(target, attrs, response):
    successful, result = isp.use_service(target=target, attrs=[attrs])
    return (successful, target_class(result) if successful else (successful, error(result))

def listen_to_isp(isp):
    #TODO: Architekture
    #dont know how a listener is defined best

if __name__ == '__main__':

    args = get_args(display_name, key, isp_ip, isp_port)  # name is variable, key is unique received on business contract with isp,
    isp = handshake_isp(args)

    window = start_window(args, isp)

    window.start_processes()
    # process 1
    while (alive):
        response = (bool successful, result)   # some kind of global or manager

        input = get_service(service, [attrs])  # waiting for input
        executing_process = multiprocessing.Process(target=input.service, args(input.attrs[], response))
        #better:
        executing_process = multiprocessing.Process(target=execute, args(input.service, input.attrs[], response))

        executeing_process.start()
        execute(executeing_process).join()  # waits for isp/server answer

        response.save()
        response.clear()
    # process 2
    while (alive):
        listening_process = listen_to_isp(isp)
        listening_process.start()
        listening_process.save()


close_window
