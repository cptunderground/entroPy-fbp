#!/usr/bin/env python3

# lib_pcap.py
# Nov 2019 <christian.tschudin@unibas.ch>


import fcntl
import os


class PCAP:

    def __init__(self, fn):
        # print("new PCAP")
        self.fn = fn
        self.f = None
        self.rd_offset = 0

    def _wr_typed_block(self, t, b):
        m = len(b) % 4
        if m:
            b += b'\x00\x00\x00\x00'
        self.f.write(t.to_bytes(4,'big'))
        l = (8 + len(b) + 4).to_bytes(4,'big')
        self.f.write(l+b+l)

    def open(self, fname, mode, offset=0): # modes: "r,w,a"
        self.f = open(fname, mode + 'b')
        # print("open", fname, self.f, offset)
        if mode in 'aw':
            fcntl.flock(self.f, fcntl.LOCK_EX)
        else:
            fcntl.flock(self.f, fcntl.LOCK_SH)
        if mode == 'w':
            # write initial sect block
            self._wr_typed_block(0x0A0D0D0A,
                     0x1A2B3C4D.to_bytes(4, 'big') + \
                     0x00010001.to_bytes(4, 'big') + \
                     (0x7fffffffffffffff).to_bytes(8, 'big'))
            # write interface description block
            self._wr_typed_block(1,
                                 (99).to_bytes(2,'big') + \
                                 b'\00\00\00\00\00\00')
            self.f.flush()
        elif mode == 'a':
            self.f.seek(0, 2)
        else:
            # self.f.seek(offset if offset == 0 else offset-12, 0)
            self.f.seek(offset if offset == 0 else offset, 0)
        # print("writing or reading will be at", self.f.tell())

    def close(self):
        if self.f:
            # self.offset = self.f.tell()
            # print(f"closing at offset {self.f.tell()}")
            fcntl.flock(self.f, fcntl.LOCK_UN)
            self.f.close()
            self.f = None

    def read(self): # returns packets, or None
        w = None
        while True: # not self.f.eof():
            # print(f"  read at {self.rd_offset}/{self.f.tell()}")
            t = int.from_bytes(self.f.read(4), 'big')
            # print(f"typ={t}")
            # self.offset += 4
            l = int.from_bytes(self.f.read(4), 'big')
            # print(f"len={l}")
            # self.offset += 4
            if l < 12:
                break
            b = self.f.read(l-12)
            # self.offset += l-12
            _ = self.f.read(4)
            # self.offset += 4
            if t == 3:
                l = int.from_bytes(b[:4], 'big')
                # print(f"len2={l}")
                w = b[4:4+l]
                break
        self.rd_offset = self.f.tell()
        return w

    def __iter__(self):
        return self

    def __next__(self):
        block = self.read()
        if not block:
            raise StopIteration
        return block

    def write(self, pkt):
        self._wr_typed_block(3, len(pkt).to_bytes(4,'big') + pkt)


# ----------------------------------------------------------------------

if __name__ == '__main__':
    print('ok')
