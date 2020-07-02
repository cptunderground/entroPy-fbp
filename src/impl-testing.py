from lib import pcap

if __name__ == '__main__':
    '''
    This acted as testing file
    '''
    print("---------------------")
    pcap.dump("./feeds/isp001/isp001_cli002.pcap")
    print("---------------------")
    pcap.dump("./feeds/cli002/cli002_ser001.pcap")
