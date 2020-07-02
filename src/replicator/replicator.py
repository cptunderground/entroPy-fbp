from shutil import copy2
import os

class Replicator():
    '''
    This class holds a source file and a destination, source is copied to destination
    '''
    def __init__(self, name, source, destination):
        self.name = name
        self.source_path = f'{source}'
        self.destination = f'{destination}'


    def replicate(self):
        '''
        the actual replication by copying.
        if destination does not exist it is created
        :return:
        '''
        rep_file = f'{self.destination}/{self.name}'
        if os.path.exists(rep_file):
            print('exists')
            pass
        else:
            if os.path.exists(self.destination):
                pass
            else:
                os.mkdir(self.destination)

            f = open(rep_file, 'w+')
            f.close()
        copy2(self.source_path, rep_file)
        print('Replication done')

def replicate(src,dst):
    '''
    for manual replication. if destination does not exist it is created
    :param src: source file
    :param dst: destination file
    :return:
    '''
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



    # self.replicator = Replicator(c_s_feed, 'feeds/replicator_test/test.pcap')