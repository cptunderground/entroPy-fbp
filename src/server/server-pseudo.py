if __name__ == '__main__':
    self = start()

    while (alive):
        isp_listener = start_listening_process()
        if (isp_listener.has_inc_HS):
            isp_process = isp_listener.fork()
            isp_process.announce_service(service_list)
            isp_process_list.add(isp_process)