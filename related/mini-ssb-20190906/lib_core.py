#!/usr/bin/env python3

# lib_core.py
# Nov 2019 <christian.tschudin@unibas.ch>


import cbor2
import Chessnut
import copy
import hashlib
import hmac
import nacl.secret
import nacl.signing
import nacl.encoding
import nacl.public
import nacl.exceptions
import sys
import traceback
import watchdog.observers as wdo
import watchdog.events    as wde

import lib_pcap as pcap

# ---------------------------------------------------------------------------

ENC_CLR = 0
ENC_BOX = 1 # SSB ED25519
ENC_SCH = 2 # AES with hmac tag
ENC_MBX = 3

def serialize(data_struct):
    return cbor2.dumps(data_struct)

def deserialize(data):
    return cbor2.loads(data)

SIGNINGALGO_SHA256_ED25519 = 0x01

def _sbox_open(data, nonce, key):
    return nacl.bindings.crypto_secretbox_open(data, nonce, key)

# ---------------------------------------------------------------------------

class CONFIG():

    def __init__(self, fn):
        self.fn = fn
        self.kv = {}

    def load(self):
        p = pcap.PCAP(self.fn)
        p.open(self.fn, 'r')
        for e in p:
            e = cbor2.loads(e)
            e[1] = cbor2.loads(e[1])
            if e[0] != ENC_CLR or e[1][0] != 'set':
                continue
            self.kv[e[1][1]] = e[1][2]
        p.close()

    def dump(self):
        p = pcap.PCAP(self.fn)
        p.open(self.fn, 'w')
        for k,v in self.kv.items():
            p.write( cbor2.dumps([ENC_CLR, cbor2.dumps( ('set',k,v) )]) )
        p.close()

    def __setitem__(self, k, v):
        self.kv[k] = v

    def __getitem__(self,k):
        return self.kv[k]
    

class KEY_RING:

    def __init__(self, owner=None):
        # print(f"KEY_RING {owner} {self}")
        self.owner = owner
        # self.subs = []
        # we should record when encr/decr was last made
        # and have a set of "hot" keys to try out first
        self.pk, self.sk, self.skc = None, None, None

    def dump(self, fn):
        pass

    def load(self, fn):
        pass

    def new_ed25519(self):
        kp = nacl.signing.SigningKey.generate()
        self.pk = kp.verify_key._key
        self.sk = kp._signing_key
        self.skc = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(self.sk
)
    def sign_ed25519(self, blob):
        signing_key = nacl.signing.SigningKey(self.sk)
        signed = signing_key.sign(blob)
        return signed.signature[:64]

    @staticmethod
    def box_ed25519(payload, rcpts):
        # rcpts is a list of the respective public keys (bytes)
        # returns the ciphertext (bytes)
        if len(rcpts) > 8:
            return None
        kp = nacl.bindings.crypto_box_keypair()
        keks = []  # key encryption keys
        for r in rcpts:
            r = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(r)
            keks.append(nacl.bindings.crypto_scalarmult(kp[1], r))
        nonce = nacl.bindings.randombytes(24)
        dek = nacl.bindings.randombytes(32) # data encryption key
        ndek = bytes([len(rcpts)]) + dek # number of rcpts, followed by dek
        c = nonce + kp[0] # nonce followed by public key
        for k in keks:    # append wrapped DEKs for all recpts
            c += nacl.bindings.crypto_secretbox(ndek, nonce, k)
        return c + nacl.bindings.crypto_secretbox(payload, nonce, dek)

    def unbox_ed25519(self, ciphertext):
        # returns decoded data (bytes)
        # print(f"{str(self.skc)[:10]} {str(ciphertext)[:10]}" + '\n\r')
        nonce = ciphertext[:24]
        mykek = nacl.bindings.crypto_scalarmult(self.skc, ciphertext[24:56])
        rcpts = ciphertext[56:]
        for i in range(8):
            if len(rcpts) < 49:
                return None
            try:
                # print('try')
                dek = _sbox_open(rcpts[:49], nonce, mykek)
                return _sbox_open(ciphertext[56+dek[0]*49:],
                                  nonce, dek[1:])
            except:
                # print('decrypt failed')
                pass
            rcpts = rcpts[49:]
        # print("no decrypt")
        return None

    @staticmethod
    def keybox_ed25519(key, rcpts):
        # key is 32 bytes to be encrypted
        # rcpt is a public keys (bytes)
        nonce = nacl.bindings.randombytes(24)
        kp = nacl.bindings.crypto_box_keypair()
        lst = [nonce, kp[0]]
        for r in rcpts:
            r = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(r)
            kek = nacl.bindings.crypto_scalarmult(kp[1], r)
            lst.append(nacl.bindings.crypto_secretbox(key, nonce, kek))
        return lst

    def unkeybox_ed25519(self, lst):
        # returns decoded data (bytes)
        nonce, kp = lst[:2]
        kek = nacl.bindings.crypto_scalarmult(self.skc, kp)
        for ciphertext in lst[2:]:
            try:
                return _sbox_open(ciphertext, nonce, kek)
            except:
                continue
        return None

    @staticmethod
    def validate_ed25519(pk, blob, signature):
        verify_key = nacl.signing.VerifyKey(public)
        try:
            verify_key.verify(blob, signature)
        except nacl.exceptions.BadSignatureError:
            return False
        else:
            return True

    def add_subchannel(self, hkey, dkey):
        for s in self.subs:
            if s.hkey == hkey:
                s.dkey.insert(0, dkey)
                return s
        self.subs.append(SUBCHANNEL(hkey,dkey))
        return self.subs[-1]

    def unwrap(self, cipherblock, sch=None): # [enc_tag,ciphertext]
        # print("unwrap", cipherblock, sch)
        c = None
        try:
            if cipherblock[0] == ENC_BOX:
                return ('box', self.unbox_ed25519(cipherblock[1]))
            if cipherblock[0] == ENC_SCH:
                ciphertext = cipherblock[1]
                if sch:
                    return (sch, sch.unwrap(ciphertext))
                # try out all subchannel keys we have
                mac = ciphertext[-32:]
                msg = ciphertext[:-32]
                for sch in self.subs:
                    # print(f"** trying {sch}, {sch.hkey}")
                    txt = sch.match_and_unwrap(mac, msg)
                    if txt != None:
                        return (sch, txt)
        except Exception as e:
            # print(e)
            pass
        return (None, None)

    pass


class EVENT:
    # obj for received events, stored in the node's database

    def __init__(self, i=None, s=0, p=None, c=None):
        # event fields:
        self.raw = None     # wire bytes
        self.prodID = i
        self.prodSeq = s
        self.prodPrev = p   # hash-chain, as a hash value
        self.cipherblock = c    # [tag,ciphertext], not serialized
        self.signalgo = SIGNINGALGO_SHA256_ED25519
        # STOR-level event chain:
        self.storPrev = None  # as an event obj

    def from_wire(self, w, keyring=None):
        self.raw = w
        meta_cbor, signature, c = deserialize(w)
        meta = deserialize(meta_cbor)
        self.prodID, self.prodSeq, self.prodPrev, \
            self.signalgo, c_hash = meta[:5]
        assert self.signalgo == SIGNINGALGO_SHA256_ED25519
        # should check signature
        assert c_hash == hashlib.sha256(c).digest()
        self.cipherblock = deserialize(c)

    def to_wire(self): # , encr):
        if self.raw == None:
            # c = cbor2.dumps(encr(cbor2.dumps(self.ciphertext)))
            c = serialize(self.cipherblock)
            c_hash = hashlib.sha256(c).digest()
            meta = [self.prodID, self.prodSeq, self.prodPrev,
                    self.signalgo, c_hash]
            meta_cbor = serialize(meta)
            meta_hash = hashlib.sha256(meta_cbor).digest()
            signature = meta_hash # ...
            self.raw = serialize([meta_cbor, signature, c])
        return self.raw

    def name(self):
        return f"{self.prodID}:{self.prodSeq}"

    def pred_name(self):
        if self.prodSeq == 1:
            return None
        return f"{self.prodID}:{self.prodSeq - 1}"

    def __repr__(self):
        return self.name()

    # def __str__(self):
    #     return('X')
    #     return f"e({self.name()},{self.content})"  # ,h={self.prodPrev})"

    pass


class EVENT_VIEW():
    # obj for delivered events, with decrypted (if possible) content

    def __init__(self, e):
        self.e = e
        self.decrypted = False
        self.content = None # if not decryted, else cleartext
        self.sch = None     # from which subchannel this event was incoming from
        # view-local: (linked list of incoming events)
        self.viewPrev = None
        # NOVELTY_SOURCE-level
        self.pred = None  # (content-level) 'ref' field
        self.succ = []    # list of event_views (without the hash-chain succ)

    def set_pred(self, p):
        # assert self.pred == None
        self.pred = p

    def add_succ(self, p):
        if not p in self.succ:
            self.succ.append(p)

    def name(self):
        return self.e.name()

    def __repr__(self):
        return self.name()

    def __str__(self):
        return f"ev({self.name()},{self.content})"  # ,h={self.prodPrev})"

    pass


class NOVELTY_SOURCE: # list of subscribers and observers, dispatching

    def __init__(self, view):
        self.view = view
        self.subscribers = {}
        self.subscribercnt = 0
        self.obsv = {}
        self.obsvcnt = 0
        self.loose = [] # list of events w/o 'ref' or not-yes-existing 'ref'

    def __contains__(self, e): # subsclasses should overwrite this method
        return self.view.name_to_event(e.name()) != None

    def _process_ref_(self, ev):
        if 'ref' in ev.content:
            ref = ev.content['ref']
            r = self.name_to_event(ref)
            if r == None: # not yet received
                self.loose.append(ev)
            else:
                ev.set_pred(r)
                r.add_succ(ev)
        for o in self.loose:
            if o.content['ref'] == ev.name():
                self.loose.remove(o)
                o.set_pred(ev)
                ev.add_succ(o)
        
    def subscribe(self, novelty_obj, filt, last_seen = None):
        # print("subscribe", self, type(self), novelty_obj, filt)
        h = self.subscribercnt
        self.subscribercnt += 1
        self.subscribers[h] = (novelty_obj, filt)
        return
        '''
        if last_seen == None:
            last_seen = self.view.latest
        e = self.view.latest
        while e != None and e != last_seen:
            if filt(e):
                novelty_obj.incoming(e)
            e = e.viewPrev
        return h
        '''

    def unsubscribe(self, h):
        if h in self.subscribers:
            del self.subscribers[h]

    def observe(self, cb, last_seen):
        h = self.obsvcnt
        self.obsvcnt += 1
        self.obsv[h] = cb
        return h

    def unobserve(self, h):
        if h in self.obsv:
            del self.obsv[h]

    def inform_observers(self, update):
        for f in self.obsv.values():
            try:
                f(update)
            except:
                pass

    def incoming(self, e):
        # 'e' can be received several times, e.g. when decrypted version
        # becomes available
        # print(f"incoming (on {self.__class__.__name__} obj): ", e)

        # if len(self.subscribers) == 0:
        #     print(f"no subscribers in {self}")
        for novelty_obj,filt in self.subscribers.values():
            if filt==None or filt(e): # filter
                novelty_obj.incoming(e)
            else:
                pass
                # print(f"filter not matching {filt}")

class MODIFIED_CB(wde.FileSystemEventHandler):
    
    def __init__(self, aolg, fn):
        super().__init__()
        self.aolg = aolg
        self.fn = fn

    def on_modified(self, e):
        if e.src_path != './' + self.fn:
            return
        self.aolg.modified()


class APPEND_ONLY_LOG(NOVELTY_SOURCE):

    def __init__(self, prodID, fn=None, obs=None):
        super().__init__(None)
        self.prodID = prodID
        self.fn = fn
        self.obs = None
        self.lg = []
        if fn and obs:
            obs.schedule(MODIFIED_CB(self,fn), '.', recursive=True)
        self.pcap = pcap.PCAP(fn)

    def __len__(self):
        return len(self.lg)

    def __getitem__(self, i):
        return self.lg[i]

    def restore(self):
        # print(f"AOLG restore {self.fn}")
        self.pcap.open(self.fn, 'r')
        cnt = 0
        for w in self.pcap:
            e = EVENT()
            e.from_wire(w)
            self.lg.append(e)
            cnt += 1
        self.pcap.close()
        # print(f"  {cnt} entries restored")

    def modified(self):
        self.pcap.open(self.fn, 'r', self.pcap.rd_offset)
        # print(f"{self.fn} was modified:")
        cnt = 0
        lst = []
        for w in self.pcap:
            e = EVENT()
            e.from_wire(w)
            lst.append(e)
        self.pcap.close()
        for w in lst:
            super().incoming(e)
            # self.lg.append(e)
            cnt += 1
        # print(f"  {cnt} entries loaded from {self.fn}")
        
    def _mk_event(self, c):
        e = EVENT(i=self.prodID, s=len(self.lg)+1,
                  p=None if len(self.lg) == 0 \
                         else hashlib.sha256(self.lg[-1].raw).digest(),
                  c=c)
        # TODO: signing
        e.raw = e.to_wire()
        return e

    def extend(self, c): # , encr):
        # creates new log extension for content c (incl signing)
        e = self._mk_event(c)
        if self.fn:
            self.pcap.open(self.fn, 'a')
            self.pcap.write(e.to_wire())
            self.pcap.close()
        # the watchdog functionality will see and read this new event,
        # which is intercepted by the STORAGE layer (incoming_wire) that
        # will call the append() method below
        return e

    def append(self, e):
        # print("AOLG append", e, type(e))
        # stores the given event e
        # TODO: validate
        try:
            assert e.prodID == self.prodID
            assert e.prodSeq == len(self.lg) + 1
        except:
            print("missmatch in append:")
            print(" ", e.prodID, e.prodSeq, len(self.lg))
            return
        e.prodPrev = None if e.prodSeq == 1 else self.lg[-1]
        self.lg.append(e)
        return e

    pass

# ---------------------------------------------------------------------------

class STORAGE(NOVELTY_SOURCE): # SSB's waist, the node's DB

    def __init__(self):
        super().__init__(self)
        self.stor = self
        self.seq = 0
        self.latest = None
        self.logs = {}

    def attach_feed(self, prodID, fn, obs=None):
        if not prodID in self.logs:
            lg = APPEND_ONLY_LOG(prodID, fn, obs=obs)
            self.logs[prodID] = lg
            lg.subscribe(self, None, None)

    def restore(self):
        for lg in self.logs.values():
            # print(f"STOR restore {lg}")
            lg.restore()
            for e in lg:
                # print(e)
                e.storPrev = self.latest
                self.latest = e
                self.seq += 1
                e.nodeSeq = self.seq
                super().incoming(e)

    def name_to_event(self, n):
        i,s = n.split(':')
        if not i in self.logs:
            return None
        s = int(s)
        if s < 1 or s > len(self.logs[i]):
            return None
        return self.logs[i][s-1]

    def incoming_wire(self, w):
        e = EVENT()
        e.from_wire(w)
        self.incoming(e)

    def incoming(self, e):
        # print("STOR incoming:", e)
        if not e.prodID in self.logs:
            self.logs[e.prodID] = APPEND_ONLY_LOG(e.prodID)
        self.logs[e.prodID].append(e)
        # create node-wide hash-chain of incoming events:
        e.storPrev = self.latest
        self.latest = e
        self.seq += 1
        e.nodeSeq = self.seq
        # pass the event to any subscribers, done by the super class:
        super().incoming(e)

    def extend(self, kr, cipherblock):
        # print(f"STOR extend")
        lg = self.logs[kr.owner]
        lg.extend(cipherblock)

    pass


class USER_VIEW(NOVELTY_SOURCE):

    def __init__(self, stor, kr):
        super().__init__(self)
        self.real_stor = stor
        self.latest = None
        self.viewCnt = 0
        self.kr = kr
        self.feeds = {}
        self.ev = {} # name to EVENT_VIEW

    def __contains__(self, ev):
        return ev.e.prodID in self.feeds \
               and ev.e.prodSeq <= len(self.view.real_stor.logs[ev.e.prodID])

    def incoming(self, e):
        # print("VIEW incoming:", e, f"view={self}")
        assert e.prodID in self.feeds
        # create view-wide hash-chain of incoming events:
        ev = EVENT_VIEW(e)
        ev.viewPrev = self.latest
        self.latest = ev
        self.ev[e.name()] = ev
        self.viewCnt += 1
        super().incoming(ev)
        return
        '''
        # pass the event to any subscribers if decryptable:
        sch,c = self.kr.unwrap(ev.e.cipherblock)
        # print(c, ev.e.cipherblock)
        if c != None:
            ev.content = deserialize(c)
            ev.decrypted = True
            ev.sch = sch
        if ev.decrypted:
            self._process_ref_(ev)
            super().incoming(ev)
        '''

    def follow(self, prodIDlst, prio=0): # 0=highest prio, range up to 10
        for prodID in prodIDlst:
            if not prodID in self.feeds:
                h = self.real_stor.subscribe(self,
                                       lambda e,i=prodID: e.prodID == i, None)
                self.feeds[prodID] = h

    def unfollow(self, prodIDlst):
        for prodID in prodIDlst:
            if prodID in self.feeds:
                self.real_stor.unsubscribe(self.feeds[prodID])
                del self.feeds[prodID]

    def name_to_event(self, n):
        return None if not n in self.ev else self.ev[n]

    def reveal_subchannel(self, sch_demux, sch=None):
        # print("reveal", self.viewCnt, type(sch_demux))
        ev = self.latest
        while ev:
            if not ev.decrypted and ev.e.cipherblock[0] == ENC_SCH:
                # print("reveal *", ev.e.cipherblock)
                try:
                    sch, c = sch_demux.unwrap(ev.e.cipherblock, sch)
                except Exception as e:
                    # print(e)
                    c = None
                if c != None:
                    ev.content = deserialize(c)
                    ev.decrypted = True
                    ev.sch = sch
                    # print(ev.content)
                    self._process_ref_(ev)
                    sch.incoming(ev)
            ev = ev.viewPrev

    def compare(self, e1, e2): # causality ordering
        # returns -1 if e1 <= 2, 0 if concurrent, 1 if e1 > e2
        if e1 == None or e2 == None:
            return 0
        if e1.prodID == e2.prodID:
            return -1 if e1.prodSeq <= e2.prodSeq else 1
        else:
            x = e1.pred
            while x != None:
                if x.prodID == e2.prodID:
                    return -1 if x.prodSeq-1 <= e2.prodSeq else 1
                x = x.pred
            x = e2.pred
            while x != None:
                if x.prodID == e1.prodID:
                    return -1 if e1.prodSeq-1 <= x.prodSeq else 1
                x = x.pred
        return 0

    def write(self, datastruct):
        # print(f"USER_VIEW write({datastruct})")
        e = self.real_stor.extend(self.kr, datastruct)

    pass


class PRIVATE_CHANNEL(NOVELTY_SOURCE):

    def __init__(self, view):
        super().__init__(view)
        view.subscribe(self, lambda ev: not ev.decrypted and \
                                        ev.e.cipherblock[0] == ENC_BOX, None)
        self.ev = {}

    def name_to_event(self, n):
        return None if not n in self.ev else self.ev[n]

    def incoming(self, ev):
        # print("PRIVATE_CHANNEL incoming", ev, ev.e.cipherblock[0],
        #       self.view.kr.sk)
        c = self.view.kr.unbox_ed25519(ev.e.cipherblock[1])
        if c != None:
            ev.decrypted = c
            ev.content = deserialize(c)
            ev.sch = 'box'
            self.ev[ev.name()] = ev
            self._process_ref_(ev)
            super().incoming(ev)
        else:
            pass

    def wrap(self, cleartext, recpts):
        return self.view.kr.box_ed25519(cleartext, recpts)

    pass


class SUBCHANNEL_DEMUX(NOVELTY_SOURCE):

    def __init__(self, view):
        super().__init__(view)
        self.my_groups = {}      # ref ~ where I am owner
        self.subs = []           # subchannel_inst
        # self.rooms = {}          # ref ~ open rooms (instances)
        view.subscribe(self, lambda ev: not ev.decrypted and \
                                        ev.e.cipherblock[0] == ENC_SCH, None)

    def __len__(self):
        return len(self.my_memberships)

    def __getitem__(self, i):
        return self.my_memberships[i]

    def unwrap(self, cipherblock, sch=None): # [tag,ciphertext]
        # print("unwrap", cipherblock, sch)
        c = None
        try:
            ciphertext = cipherblock[1]
            if sch:
                return (sch, sch.unwrap(ciphertext))
            # try out all subchannel keys we have
            mac = ciphertext[-32:]
            msg = ciphertext[:-32]
            for sch in self.subs:
                # print(f"** trying {sch}, {sch.hkey}")
                txt = sch.match_and_unwrap(mac, msg)
                if txt != None:
                    return (sch, txt)
        except Exception as e:
            # print(e)
            pass
        return (None, None)

    def new_subchannel(self, members):
        hkey = nacl.bindings.randombytes(16)
        dkey = nacl.bindings.randombytes(32)
        return self.add_subchannel(hkey, dkey, members)

    def add_subchannel(self, hkey, dkey, members):
        sch = SUBCHANNEL_INSTANCE(self, hkey, dkey, members=members)
        self.subs.append(sch)
        return sch

    def incoming(self, ev):
        # print("SUBCHANNEL_DEMUX incoming", self, ev, self.view.kr.owner)
        sch, txt = self.unwrap(ev.e.cipherblock)
        if txt != None:
            ev.content = deserialize(txt)
            # print(" ///", ev.content)
            ev.decrypted = True
            ev.sch = sch
            self.view._process_ref_(ev)
            sch.incoming(ev)
            return
        else:
            pass
        # print("---??? unknown sch")
        # traceback.print_stack()
        return

    def write(self, datastruct):
        # print(f"SUBCH_DEMUX write({datastruct})")
        e = self.view.write(datastruct)

    def open(self, ref): # returns _INSTANCE obj
        pass

    pass


class SUBCHANNEL_INSTANCE(NOVELTY_SOURCE):

    def __init__(self, view, hkey=None, dkey=None, display=None,
                 members=[], owners=[]):
        super().__init__(view)
        self.hkey = hkey
        self.dkeys = [dkey] if dkey else None
        self.members = members
        self.owners = owners
        self.seqno = 0 # for commands (sent by one of the owners)
        self.left = False

    def add_member(self, m):
        if not m in self.members:
            self.members.append(m)

    def wrap(self, cleartext):
        nonce = nacl.bindings.randombytes(24)
        msg = nonce + nacl.bindings.crypto_secretbox(cleartext, nonce,
                                                     self.dkeys[0])
        return msg + hmac.digest(self.hkey, msg, hashlib.sha256)

    def match_and_unwrap(self, mac, msg):
        if hmac.compare_digest(mac, hmac.digest(self.hkey,msg,hashlib.sha256)):
            for dkey in self.dkeys:
                try:
                    return _sbox_open(msg[24:], msg[:24], dkey)
                except nacl.exceptions.ValueError:
                    continue
        return None

    def unwrap(self, ciphertext):
        msg = ciphertext[:-32]
        for dkey in self.dkeys:
            try:
                return _sbox_open(msg[24:], msg[:24], dkey)
            except nacl.exceptions.ValueError:
                continue
        print("*not found")
        return None

    def rekey(self):
        # TODO: check that we are an owner
        new_dkey = nacl.bindings.randombytes(32)
        dkeys = kr.keybox_ed25519(new_dkey, [m for m in self.members])
        # print("rekey", dkeys)
        c = {'app': 'sch_mgmt', 'seqno': self.seqno+1,
             'cmd': 'rekey', 'dkeys': dkeys}
        # tell all members, via this subchannel, about the new dkey
        self.view.write([ENC_SCH, self.wrap(serialize(c))])

    def leave(self):
        if not self.left:
            c = { 'app': 'sch_mgmt', 'cmd': 'leave' }
            # tell all members, via this subchannel, about the new dkey
            self.view.write([ENC_SCH, self.wrap(serialize(c))])

    def incoming(self, ev):
        if self.left: # ignore
            return
        # print("SUBCH_INSTANCE", ev, self.subscribers)
        if ev.content['app'] == 'sch_mgmt' and 'cmd' in ev.content:
            cmd = ev.content['cmd']
            if cmd == 'rekey' and 'dkeys' in ev.content and \
               ev.content['seqno'] > self.seqno:
                # TODO: assert that this comes from an owner
                d = self.view.view.kr.unkeybox_ed25519(ev.content['dkeys'])
                if d != None:
                    # print(f"found subchannel and new dkey")
                    self.dkeys.insert(0, d)
                    self.seqno = ev.content['seqno']
                    # TODO: if the rekey msg is from us, send an OWNER cmd
                    # 
                    return
            if cmd == 'add' and 'ids' in ev.content and \
               ev.content['seqno'] > self.seqno:
                # TODO: assert that this comes from an owner
                lst = ev.content['ids']
                for prodID in lst:
                    if not prodID in self.members:
                        self.members.append(prodID)
                self.seqno = ev.content['seqno']
                return
            if cmd == 'remove' and 'ids' in ev.content and \
               ev.content['seqno'] > self.seqno:
                # TODO: assert that this comes from an owner
                lst = ev.content['ids']
                for prodID in lst:
                    if prodID in self.members:
                        self.members.remove(prodID)
                    if prodID == self.view.view.kr.pk:
                        self.left = True
                        self.inform_observers(('left'))
                self.seqno = ev.content['seqno']
                return
            # promote, demote
            if cmd == 'leave':
                # print(f"{ev.e.prodID} is leaving")
                if ev.e.prodID == self.view.view.kr.owner:
                    self.left = True
                    # print(" ...left", self.members)
                    if ev.e.prodID in self.members:
                        self.members.remove(ev.e.prodID)
                
            # print("unknown sch_mgmt cmd or..", ev)
        else:
            # print("no valid rekey cmd")
            super().incoming(ev)

    def write(self, datastruct):
        # print(f"SUBCH_INSTANCE write({datastruct})")
        e = self.view.write(datastruct)

    def close(self): # just this (memory) instance
        pass

    def terminate(self, kr): # must be owner
        # to sch: {'app' = 'encrgrp', 'cmd':'terminate'}
        pass

    def add_members(self, kr, feed_id_lst): # must be owner
        # to owners: box{'app' = 'encrgrp', 'cmd':'add', .. feed_ID}
        # to member: box{'app' = 'encrgrp', 'cmd':'joined',
        #                'display':'name', hkey, dkey, list_of_owners}
        pass

    def add_owner(self, kr, feed_id_lst): # must be owner
        # to owners: box{'app' = 'encrgrp', 'cmd':'add', .. feed_ID}
        # to new o:  box{'app' = 'encrgrp', 'cmd':'joined',
        #                'display':'name', hkey, dkey, list_of_owners}
        # to all members: sch{}
        pass

    def del_member(self, kr, feed_id): # must be owner
        # to owners: box{'app' = 'encrgrp', 'cmd':'add', .. feed_ID}
        # to all members: {'app' = 'encrgrp', 'ref', 'cmd':'rekey', dkey}
        pass

    #def rekey(self): # must be owner
    #    # to all members: {'app' = 'encrgrp', 'ref', 'cmd':'rekey', dkey}
    #    pass

    def rename(self, kr, nm): # must be owner
        # to sch: {'app' = 'encrgrp', 'ref', 'cmd':'post', text}
        pass

    def post(self, kr, text):
        # to sch: {'app' = 'encrgrp', 'ref', 'cmd':'post', text}
        pass

    pass

# ---------------------------------------------------------------------------

class CHAT_APP(NOVELTY_SOURCE):
    
    def __init__(self, view):
        super().__init__(view)
        self.posts = []
        # self.chats = {} # subchannel ~ chat_instance
        view.subscribe(self, lambda e:e.content['app'] == 'chat', None)
        self.inlst = []

    def __contains__(self, ev):
        return ev in self.posts

    def incoming(self, ev):
        self.inlst.append(ev.name())
        # print("CHAT_APP incoming:", ev.content)
        # super().incoming(ev) # we have no subscribers, only observers
        w = [ev]
        while len(w) > 0:
            ev = w.pop()
            # print(f" w={w}, working on {ev}")
            if 'ref' in ev.content:
                ref = ev.content['ref']
                ref_minus_1 = ref.split(':')
                ref_minus_1 = (ref_minus_1[0], int(ref_minus_1[1])-1)
            else:
                ref, ref_minus_1 = None, (None, 0)
            pos = 0
            for i in range(len(self.posts)-1, -1, -1):
                if ref == self.posts[i].name():
                    pos = i+1
                    break
                # if self.view.compare(self.posts[i], e) == 1:
                if ev.e.prodID == self.posts[i].e.prodID and \
                   ev.e.prodSeq-1 == self.posts[i].e.prodSeq:
                    pos = i+1
                    break
                if ref_minus_1[0] == self.posts[i].e.prodID and \
                   ref_minus_1[1] == self.posts[i].e.prodSeq:
                    pos = i+1
                    break
                if self.posts[i].pred == None:
                    pos = i+1
                    break
            else:
                pass
            self.posts.insert(pos, ev)
            self.inform_observers(('insert', pos, ev))
            for s in ev.succ:
                i = self.posts.index(s)
                if i >= 0 and i < pos:
                    self.posts.remove(s)
                    self.inform_observers(('remove', i, s))
                    w.append(s)

        # in theory, we have to take all references inside this
        # message (not only 'ref'), by also looking into the post body..
        # and for new events, reconsider those events having been
        # inserted at position 0 (and before the initial message)

    def post(self, msg):
        # print(f"CHAT_INSTANCE post({msg})")
        c = { 'ref': None if len(self.posts) == 0 else self.posts[-1].name(),
              'app':'chat', 'post':msg.encode('utf8') }
        c = [ENC_SCH, self.view.wrap(serialize(c))]
        self.view.write(c)

    pass
    

class CHESS_APP(NOVELTY_SOURCE):

    def __init__(self, view):
        super().__init__(view)
        self.games = {}
        self.ev = {}
        view.subscribe(self, lambda ev: ev.decrypted and \
                                        ev.content['app'] == 'chess', None)

    def incoming(self, ev):
        # print("CHESS_APP incoming:", ev)
        self.ev[ev.name()] = ev
        self.view._process_ref_(ev)
        # super().incoming(ev)
        if 'newgame' in ev.content:
            n = ev.name()
            g = CHESS_GAME(self.view, n)
            self.games[n] = g
            self.subscribe(g, lambda e,n=n: e.content['game'] == n, None)
            self.inform_observers(('newgame', g))
        else:
            n = ev.content['game']
            g = None if not n in self.games else self.games[n]
        if g:
            x = [ev]
            while len(x) > 0:
                ev = x.pop()
                if ev in self.view.loose:
                    self.view.loose.remove(ev)
                g.incoming(ev)
                x += copy.copy(ev.succ)

    def invite(self, peerID):
        c = { 'app':'chess', 'newgame':[self.view.view.view.kr.pk,peerID] }
        c = [ENC_SCH, self.view.wrap(serialize(c))]
        self.view.write(c)

    def accept(self, gameRef):
        # a1 = a.extend(encr_a_b({'app':'chess','newgame':'A,B'})).name()
        pass

    pass


class CHESS_GAME(NOVELTY_SOURCE):

    def __init__(self, view, ref):      # , ref, a, b):
        super().__init__(view)
        self.ref = ref      # 'newgame' event
        self.players = None # (b, a)
        self.peer_pk = None
        self.cnt = -1
        self.moves = []
        self.front = None   # 'newgame' event, or latest valid move
        self.logic = Chessnut.Game()

    def __contains__(self, ev):
        return ev in self.moves

    def contains_name(self, n):
        for ev in self.moves:
            if ev.name() == n:
                return True
        return False

    def incoming(self, ev):
        # print("CHESS_GAME incoming:", ev)
        # super().incoming(ev)
        if 'newgame' in ev.content:
            self.players = ev.content['newgame']
            self.players.reverse()
            if self.players[0] == self.view.view.kr.owner:
                self.peer_pk = ev.content['pk'][0]
            else:
                self.peer_pk = ev.content['pk'][1]
            self.front = ev
            self.cnt = 0
            return
        if 'endgame' in ev.content:
            return

        while True: # len(self.front.succ) > 0:
            # print(f"  succ: {self.succ}")
            for ev in self.front.succ:
                # ev = self.names[e]
                if 'n' in ev.content and ev.content['n'] == self.cnt:
                    if ev.e.prodID != self.players[self.cnt % 2]:
                        continue
                    if not 'mv' in ev.content:
                        self.cnt += 1
                        self.inform_observers(('accepted',))
                    else:
                        try:
                            self.logic.apply_move(ev.content['mv'])
                            self.cnt += 1
                            self.moves.append(ev)
                            self.inform_observers(('move', self.cnt-1,
                                                   ev.content['mv']))
                        except:
                            self.inform_observers(('invalid', self.cnt,
                                                   ev.content['mv']))
                            pass
                    self.front = ev
                    break
            else:
                break

    def make_move(self, move):
        if self.players[self.cnt % 2] != self.view.view.kr.owner:
            return False
        try:
            copy.deepcopy(self.logic).apply_move(move)
        except Exception as e:
            return False
        msg = {'ref':self.moves[-1].name(), 'app':'chess',
               'game':self.ref, 'n':self.cnt, 'mv':move}
        pk = [self.view.view.kr.pk, self.peer_pk]
        c = [ENC_BOX, self.view.view.kr.box_ed25519(serialize(msg), pk)]
        self.view.view.write(c)
        return True

    def end_game(self):
        pass

    pass


class USER_DIR_APP(NOVELTY_SOURCE):

    def __init__(self, view):
        super().__init__(view)
        self.about = {} # targetID ~ { authorID ~ evnt }
        view.subscribe(self, lambda e:e.content['app'] == 'user_dir', None)

    def incoming(self, ev):
        # print("USER_DIR_APP incoming:", e)
        super().incoming(ev)
        if not 'id' in ev.content or not 'display' in ev.content:
            return
        i,d = ev.content['id'], ev.content['display']
        if not i in self.about:
            self.about[i] = {}
        if ev.e.prodID in self.about[i]:
            old = self.about[i][ev.e.prodID]
            if old.e.prodSeq >= ev.e.prodSeq:
                return
        self.about[i][ev.e.prodID] = ev
        if i == ev.e.prodID or not i in self.about[i]:
            self.inform_observers(f"{i} ~ '{d}'")

    def lookup(self, i):
        if not i in self.about:
            return f"name={i}"
        ndir = self.about[i]
        if i in ndir:
            return ndir[i].content['display']
        return list(ndir.values())[0].content['display']

    def assign_name(self, target_id, name):
        # print(f"USER_DIR_APP assign({target_id} <- {name})")
        c = { 'app':'user_dir', 'id':target_id, 'display':name }
        c = [ENC_SCH, self.view.wrap(serialize(c))]
        self.view.write(c)

    pass

# ---------------------------------------------------------------------------

if __name__ == '__main__':
    
    def chess_drawboard(s):
        for s in s.split(' ')[0].split('/'):
            print("+-+-+-+-+-+-+-+-+")
            while len(s) > 0:
                if s[0] in '12345678':
                    print("| " * int(s[0]), end='')
                else:
                    print(f"|{s[0]}", end='')
                s = s[1:]
            print("|")
        print("+-+-+-+-+-+-+-+-+")
    def chess_observer(game, action):
        if action[0] == 'move':
            print(f"       move {action[2]}:")
            chess_drawboard(str(game.logic))

    config = CONFIG('config.pcap')
    mode = 'run'
    if len(sys.argv) > 1:
        if sys.argv[1] == '-load':
            mode = 'load'
        elif sys.argv[1] == '-dump':
            mode = 'dump'
 
    kr = KEY_RING()

    kr_a = KEY_RING('A')
    kr_b = KEY_RING('B')
    kr_c = KEY_RING('C')

    if mode == 'load':
        config.load()
        kr_a.owner, kr_a.pk, kr_a.sk, kr_a.skc = config['/secret/A']
        kr_b.owner, kr_b.pk, kr_b.sk, kr_b.skc = config['/secret/B']
        kr_c.owner, kr_c.pk, kr_c.sk, kr_c.skc = config['/secret/C']
    else:
        kr_a.new_ed25519()
        kr_b.new_ed25519()
        kr_c.new_ed25519()
        config['/secret/A'] = [kr_a.owner, kr_a.pk, kr_a.sk, kr_a.skc]
        config['/secret/B'] = [kr_b.owner, kr_b.pk, kr_b.sk, kr_b.skc]
        config['/secret/C'] = [kr_c.owner, kr_c.pk, kr_c.sk, kr_c.skc]

    nd = STORAGE()

    uv_a = USER_VIEW(nd, kr_a)
    uv_a.follow(['A','B','C'])
    uv_b = USER_VIEW(nd, kr_b)
    uv_b.follow(['A','B','C'])

    sch_a = SUBCHANNEL_DEMUX(uv_a)
    sch_b = SUBCHANNEL_DEMUX(uv_b)
    if mode == 'load':
        hkey, dkey, members = config['/secret/subch']
        my_subch_a = sch_a.add_subchannel(hkey, dkey, members)
    else:
        my_subch_a = sch_a.new_subchannel([kr_a.pk, kr_b.pk])
        config['/secret/subch'] = [my_subch_a.hkey, my_subch_a.dkeys[0],
                                   [kr_a.pk, kr_b.pk]]
    my_subch_b = sch_b.add_subchannel(my_subch_a.hkey, my_subch_a.dkeys[0],
                                      [kr_a.pk, kr_b.pk])

    priv_a = PRIVATE_CHANNEL(uv_a)
    priv_b = PRIVATE_CHANNEL(uv_b)
    # my_subch = SUBCHANNEL_INSTANCE(None,
    #                                nacl.bindings.randombytes(16),
    #                                nacl.bindings.randombytes(32))
    # sch_a_mgmt = SUBCHANNEL_MGMT(sch_a, sch_a)

    encr1 = lambda lg,c: lg.append(lg.extend([ENC_SCH, my_subch_a.wrap(serialize(c))])).name()
    encr_a_b = lambda lg,c: lg.append(lg.extend([ENC_BOX,
                                priv_a.wrap(serialize(c),[kr_a.pk,kr_b.pk])])).name()
    encr_b_a = lambda lg,c: lg.append(lg.extend([ENC_BOX,
                               priv_b.wrap(serialize(c), [kr_a.pk,kr_b.pk])])).name()

    a,b,c = [APPEND_ONLY_LOG(n) for n in ['A', 'B', 'C']]
    a1 = encr_a_b(a, {'app':'chess','newgame':['A','B'],'pk':[kr_a.pk,kr_b.pk]})
    b1 = encr_b_a(b, {'ref':a1,'app':'chess','game':a1,'n':0})
    a2 = encr_a_b(a, {'ref':b1,'app':'chess','game':a1,'n':1,'mv':'e2e4'})
    #b2 = encr_b_a(b, {'ref':a2,'app':'chess','game':a1,'n':2,'mv':'e7e5'})
    ## a3 = encr_a_b(a, {'ref':b2,'app':'chess','game':a1,'n':2,'mv':'e2e4'})
    #a4 = encr_a_b(a, {'ref':b2,'app':'chess','game':a1,'n':3,'mv':'g1f3'})
    #b3 = encr_b_a(b, {'ref':a4,'app':'chess','game':a1,'n':4,'mv':'b8c6'})
    #a5 = encr_a_b(a, {'ref':b3,'app':'chess','game':a1,'n':5,'mv':'f1b5'})
    #b4 = encr_b_a(b, {'ref':a5,'app':'chess','game':a1,'n':6,'mv':'a7a6'})
    a6 = encr1(a, {'app':'chat','post':'first post'})
    a7 = encr1(a, {'ref':a6,'app':'chat','post':'2nd post (reply to 1st)'})
    b5 = encr1(b, {'ref':a7,'app':'chat','post':'my 1st post (reply to 2nd)'})
    b6 = encr1(b, {'ref':b5,'app':'chat','post':'my 2nd post (reply to prev)'})
    a8 = encr1(a, {'ref':a7,'app':'chat','post':'3rd post (reply to 2nd)'})
    b7 = encr1(b, {'ref':a8,'app':'chat','post':'my 3rd post (reply to 3rd)'})
    b8 = encr1(b, {'ref':b7,'app':'chat','post':'my 4th post (reply to my3)'})
    a9 = encr1(a, {'ref':b8,'app':'chat','post':'4th post (reply to my4)'})
    a10 = encr1(a, {'app':'user_dir','id':'A','display':'alice'})
    a11 = encr1(a, {'app':'user_dir','id':'B','display':'Bob2'})
    a12 = encr1(a, {'app':'user_dir','id':'A','display':'Alice'})
    b9 = encr1(b, {'app':'user_dir','id':'B','display':'Bob'})
    b10 = encr1(b, {'app':'user_dir','id':'A','display':'Alice2'})
    b11 = encr1(b, {'app':'user_dir','id':'C','display':'Carla2'})
    c1 = encr1(c, {'ref':'D:2','app':'chat','post':'fake'})
    c2 = encr1(c, {'app':'user_dir','id':'C','display':'Carla'})
    c3 = encr_a_b(c, {'app':'encrgrp', 'room':'R:1', 'cmd':'joined',
                            'hkey':nacl.bindings.randombytes(16),
                            'dkey':nacl.bindings.randombytes(32),
                            'display':'Room One', 'owners':['C']})

    chess_app_a = CHESS_APP(priv_a) # 'A:1', 'A', 'B')
    def newg(ng):
        print("chessapp update:", (ng[0],ng[1].ref))
        ng[1].observe(lambda updt: print(f"chess game {ng[1].ref} :", updt), 0)
        ng[1].observe(lambda u:chess_observer(ng[1],u), 0)
    chess_app_a.observe(newg, 0)

    chess_app_b = CHESS_APP(priv_b)
    chess_app_b.observe(newg, 0)

    chat_app = CHAT_APP(my_subch_a)
    lines = []
    def edit(cmd):
        print("chat_app update:", cmd)
        if cmd[0] == 'insert':
            lines.insert(cmd[1], cmd[2].content['post'])
        elif cmd[0] == 'remove':
            del lines[cmd[1]]
    chat_app.observe(lambda updt: edit(updt), 0)

    udir_app = USER_DIR_APP(my_subch_a)
    udir_app.observe(lambda updt: print("user_dir update:", updt),0)

    pkts = []
    if mode == 'load':
        for n in ['A', 'B', 'C']:
            p = pcap.PCAP(f"log-{n}.pcap")
            p.open(f"log-{n}.pcap", 'r')
            for e in p:
                pkts.append(e)
            p.close()
    else:
        pkts.append(a.lg[0].raw)
        for e in zip(a.lg[1:], b.lg):
            pkts.append(e[0].raw)
            pkts.append(e[1].raw)
        for e in c.lg:
            pkts.append(e.raw)

    print('---xxx1')
    for p in pkts:
        nd.incoming_wire(p)
    print('---xxx2')

    if mode == 'dump':
        config.dump()
        print(config['/secret/B'])
        for n in ['A', 'B', 'C']:
            p = pcap.PCAP(f"log-{n}.pcap")
            p.open(f"log-{n}.pcap", 'w')
            for e in nd.logs[n]:
                p.write(e.to_wire())
                if e.name() == 'B:1':
                    print('B', e.to_wire())
        p.close()

    chess_app_a2 = CHESS_APP(my_subch_a)
    ref = chess_app_a2.invite('B')
    chess_app_b2 = CHESS_APP(my_subch_b)
    chess_app_a2.accept(ref)

    uv_a.reveal_subchannel(sch_a, my_subch_a)
    # uv_a.reveal_subchannel(sch_a, my_subch)
    # uv_b.reveal_subchannel(sch_b, my_subch_b)
    # uv_a.reveal_subchannel(kr_a)
    # uv_b.reveal_subchannel(kr_b)

    my_subch_a.rekey()
    my_subch_a.rekey()
    my_subch_b.leave()
    '''
    new_dkey = nacl.bindings.randombytes(32)
    dkeys = kr.keybox_ed25519(new_dkey, [kr_a.pk, kr_b.pk])
    uv_a.write(encr_b_a({'app': 'sch_mgmt', 'cmd': 'rekey',
                         'hkey': chat_app.view.hkey,
                         'dkeys': dkeys}))
    uv_b.write(encr_a_b({'app': 'sch_mgmt', 'cmd': 'rekey',
                         'hkey': chat_app.view.hkey,
                         'dkeys': dkeys}))
    # chat_app.view.rekey()
    '''
    chat_app.post('test')

    print("\nUV novelty source: (ref <- event <- succ)")
    ev = uv_a.latest
    while ev:
        print(f"{ev.pred.name() if ev in uv_a and ev.pred else None} <- {ev.name()} <- {[x for x in ev.succ if x in uv_a]}")
        ev = ev.viewPrev

    print("\nCHESS_GAME moves:")
    for g in chess_app_a.games:
        print(f"game={g}",
              [(x.content['n'],x.content['mv']) \
               for x in chess_app_a.games[g].moves])
    for g in chess_app_b.games:
        print(f"game={g}",
              [(x.content['n'],x.content['mv']) \
               for x in chess_app_b.games[g].moves])

    print(f"\nCHAT_APP sorted posts ({len(chat_app.posts)}/{len(chat_app.inlst)}/{len(lines)}):")
    for ev in chat_app.posts:
        t = f" // ref to {ev.content['ref']}" if 'ref' in ev.content else ''
        print(f"{ev.name()} : '{ev.content['post']}'{t}")
    for l in lines:
        print(l)
    print(f"{sorted(chat_app.inlst)}")

    udir_app.assign_name('A', 'ALICE')
    print("\nUSER_DIR_APP:")
    for i in ['A', 'B', 'C']:
        print(f"{i} -> '{udir_app.lookup(i)}'")

    print()
    e_ = nd.stor.latest
    d = {}
    while e_:
        p = set()
        if e_.prodPrev:
            p.add(e_.pred_name())
        # if 'ref' in e_.content:
        #     p.add(e_.content['ref'])
        d[e_.name()] = p
        e_ = e_.storPrev
    for v in [uv_a, uv_b]:
        e_ = v.latest
        while e_:
            if e_.pred:
                d[e_.name()].add(e_.pred.name())
            e_ = e_.viewPrev
    print("partial order:", d)
    from toposort import toposort, toposort_flatten
    print("topologically sorted:", list(toposort(d)))
    lin = toposort_flatten(d)
    print("linearized:", lin)
    print()

    print(f"chat: {[n for n in lin if uv_a.ev[n] in chat_app]}")
    for g in chess_app_a.games.values():
        print(f"chess: {[n for n in lin if uv_a.ev[n] in g]}")
    for g in chess_app_b.games.values():
        print(f"chess: {[n for n in lin if uv_b.ev[n] in g]}")

    print()
    print(f"number of dkeys in subchannel: {len(my_subch_a.dkeys)}")

# eof
