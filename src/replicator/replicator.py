from shutil import copy2
import os

class Replicator():
    def __init__(self, name, source, destination):
        self.name = name
        self.source_path = f'{source}'
        self.destination = f'{destination}'

    def replicate(self):
        rep_file = f'{self.destination}/{self.name}'
        if os.path.exists(rep_file):
            print('exists')
            pass
        else:
            f = open(rep_file, 'w+')
            f.close()
        copy2(self.source_path, rep_file)

def replicate(src,dst):
    try:
        if os.path.exists(dst):
            print('exists')
            pass
        else:
            f = open(dst, 'w+')
            f.close()
        copy2(src, dst)
    except:
        print('could not replicate')
def test_replicate():
    src = f'c/client01_isp.pcap'
    dst = f'i/client01_isp_cp.pcap'
    r = Replicator(src, dst)
    r.replicate()


if __name__ == '__main__':
    test_replicate()

    # self.replicator = Replicator(c_s_feed, 'feeds/replicator_test/test.pcap')