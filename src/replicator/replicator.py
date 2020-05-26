from shutil import copy2
import os

class Replicator():
    def __init__(self, source_dir, dest_dir, log):
        self.source_path = f'feeds/{source_dir}/{log}'
        self.dest_path = f'feeds/{dest_dir}/{log}'

    def replicate(self):
        if os.path.exists(self.dest_path):
            print('exists')
            pass
        else:
            f = open(self.dest_path, 'w+')
            f.close()
        copy2(self.source_path, self.dest_path)

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