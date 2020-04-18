

#services
#first
def echo():
    isp.use_service(target=echo, attrs=[attrs])
    return echo_string

def ping():
    isp.use_service(target=ping, attrs=[attrs])
    return ping_string

def introduceMe(server):
    isp.use_service(target=introduce, attrs=[attrs])
    return bool_successful

def detruceMe(server):
    isp.use_service(target=detruce, attrs=[attrs])
    return bool_successful
#better
def execute(target, attrs):
    isp.use_service(target=target, attrs=[attrs])
    return (successful, answer) if successful else (successful, error)

if __name__ == '__main__':

    args = get_args(display_name, key, isp_ip, isp_port) #name is variable, key is unique received on business contract with isp,
    isp = handshake_isp(args)

    window = start_window(args, isp)

    window.start_processes()
        #process 1
        while (running):
        input = get_service(service, [attrs]) #waiting for input
        execute(target=input.service, attrs=input.[attrs])

        #process 2
        while (running):
        listen_to_isp()


    close_window