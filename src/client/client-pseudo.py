# services
# first
def echo():
    isp.use_service(target=echo, attrs=[attrs])
    return echo_string


def ping():
    isp.use_service(target=ping, attrs=[attrs])
    return ping_string


def introduce_me(server):
    isp.use_service(target=introduce, attrs=[attrs])
    return bool_successful


def detruce_me(server):
    isp.use_service(target=detruce, attrs=[attrs])
    return bool_successful


# better
def execute(target, attrs):
    isp.use_service(target=target, attrs=[attrs])
    return (successful, target_class(result) if successful else (successful, error(result))


if __name__ == '__main__':

    args = get_args(display_name, key, isp_ip,
                    isp_port)  # name is variable, key is unique received on business contract with isp,
    isp = handshake_isp(args)

    window = start_window(args, isp)

    window.start_processes()
    # process 1
    while (alive):
        response = (bool successful, result)   # some kind of global or manager

        input = get_service(service, [attrs])  # waiting for input
        executeing_process = execute(target=input.service, attrs=input.[attrs], res=response)
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
