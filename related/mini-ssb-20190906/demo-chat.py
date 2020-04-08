#!/usr/bin/env python3

# demo-chat.py
# Nov 2019 <christian.tschudin@unibas.ch>


import cbor2
import copy
import curses
import sys
import traceback
import watchdog.observers as wdo

import lib_core as core
import lib_pcap as pcap

trace = None
prog = ' chat demo'

def main(stdscr, argv):
    global trace

    if len(argv) < 2:
        trace = f"usage: {sys.argv[0]} OWNER PEERS" + '\n' + \
                f"   ex: {sys.argv[0]}  A  B,C"
        return

    win = None

    owner = argv[1]
    peers = [] if len(argv) == 2 else argv[2].split(',')

    observer = wdo.Observer()
    observer.start()

    config = core.CONFIG('config.pcap')
    config.load()

    secrets = config[f"/secret/{owner}"]
    kr = core.KEY_RING()
    kr.owner, kr.pk, kr.sk, kr.skc = secrets

    nd = core.STORAGE()
    uv = core.USER_VIEW(nd, kr)
    uv.follow([owner] + peers)
    sch = core.SUBCHANNEL_DEMUX(uv)
    hkey, dkey, members = config['/secret/subch']
    my_subch = sch.add_subchannel(hkey, dkey, members)
    chat_app = core.CHAT_APP(my_subch)

    lines = []
    def edit(cmd):
        try:
            if cmd[0] == 'insert':
                txt = cmd[2].content['post']
                if type(txt) == bytes:
                    txt = txt.decode('utf8')
                # txt = f"{cmd[2].e.name()}  '{txt}' "
                txt = f"{cmd[2].e.name()[0]}: {txt}"
                # if 'ref' in cmd[2].content:
                #     txt += f" (ref={cmd[2].content['ref']})"
                # txt += f" len={len(chat_app.posts)}"
                lines.insert(cmd[1], txt)
                if win:
                    win.addstr(f"| {txt}" + '\n')
                    win.refresh()
            elif cmd[0] == 'remove':
                del lines[cmd[1]]
        except:
            global trace
            trace = traceback.format_exc()
    chat_app.observe(lambda update: edit(update), 0)

    for n in [owner] + peers:
        nd.attach_feed(n, f"log-{n}.pcap", obs=observer)
    nd.restore()

    curses.echo()
    curses.curs_set(0)
    stdscr.scrollok(False)
    stdscr.addstr(0,0, ('-' * (curses.COLS-len(prog)-1)) + prog)
    stdscr.hline(curses.LINES-2,0,'-',curses.COLS-1)
    txt = " exit with CTRL-C"
    stdscr.addstr(curses.LINES-2, curses.COLS-len(txt)-1, txt)
    stdscr.refresh()

    win = curses.newwin(curses.LINES-3,curses.COLS-2,1,0)
    win.scrollok(True)
    win.idlok(True)
    win.clear()
    win.move(0,0)

    for l in lines:
        win.addstr(f"| {l}" + '\n')
    win.refresh()
    while True:
        try:
            stdscr.addstr(curses.LINES-1, 0, f"{kr.owner}> _")
            stdscr.clrtoeol()
            stdscr.move(curses.LINES-1, 3)
            stdscr.refresh()
            post = stdscr.getstr(curses.LINES-1, 3)
        except KeyboardInterrupt:
            print('\nterminating ...')
            break
        except Exception as e:
            trace = traceback.format_exc()
            break
        if len(post) != 0:
            chat_app.post(post.decode('utf8'))

    observer.stop()
    observer.join()
    
# ----------------------------------------------------------------------
if __name__ == '__main__':

    curses.wrapper(lambda stdscr: main(stdscr, sys.argv))
    if trace:
        print(trace)

# eof
