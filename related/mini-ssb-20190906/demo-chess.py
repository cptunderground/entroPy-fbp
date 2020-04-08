#!/usr/bin/env python3

# demo-chess.py
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
prog = ' chess demo'
the_game = None
kr = None

def main(stdscr, argv):
    global trace, the_game, kr

    def chess_drawboard(s):
        # win.clear()
        for s in s.split(' ')[0].split('/'):
            win.addstr("+-+-+-+-+-+-+-+-+\n")
            while len(s) > 0:
                if s[0] in '12345678':
                    win.addstr("| " * int(s[0]))
                else:
                    win.addstr(f"|{s[0]}")
                s = s[1:]
            win.addstr("|\n")
        win.addstr("+-+-+-+-+-+-+-+-+\n")
        # win.refresh()

    def chess_observer(game, action):
        global the_game

        # win.clear()
        try:
            if action[0] == 'accepted':
                the_game = game
            elif action[0] == 'move':
                win.addstr("\n" + f"       move {action[2]}:" + '\n')
                # win.refresh()
            chess_drawboard(str(game.logic))
            me = 'your move next' if game.players[game.cnt % 2] == kr.owner \
                    else 'other side to move'
            win.addstr(me + '\n')
            win.refresh()
        except:
            pass

    if len(argv) < 2:
        trace = f"usage: {sys.argv[0]} OWNER PEERS" + '\n' + \
                f"   ex: {sys.argv[0]}  A  B,C"
        return

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
    win.refresh()

    owner = argv[1]
    peers = [] if len(argv) == 2 else argv[2].split(',')

    observer = wdo.Observer()
    observer.start()

    config = core.CONFIG('config.pcap')
    config.load()

    secrets = config[f"/secret/{owner}"]
    kr = core.KEY_RING(owner)
    kr.owner, kr.pk, kr.sk, kr.skc = secrets

    nd = core.STORAGE()
    uv = core.USER_VIEW(nd, kr)
    uv.follow([owner] + peers)
    priv = core.PRIVATE_CHANNEL(uv)
    chess_app = core.CHESS_APP(priv)
    moves = []
    def newg(ng):
        try:
            win.addstr(f"chessapp update: {(ng[0],ng[1].ref)}" + '\n')
            # ng[1].observe(lambda updt,ng=ng: win.addstr(f"chess game {ng[1].ref} : {updt}" + '\n'), 0)
            ng[1].observe(lambda u,ng=ng:chess_observer(ng[1],u), 0)
            win.refresh()
        except:
            trace = traceback.format_exc()
            pass
    chess_app.observe(newg, 0)

    for n in [owner] + peers:
        nd.attach_feed(n, f"log-{n}.pcap", obs=observer)
    nd.restore()

    color = 'white' if the_game.players[0] != kr.owner else 'black'
    while True:
        win.refresh()
        try:
            stdscr.addstr(curses.LINES-1, 0, f"{color}> _")
            stdscr.clrtoeol()
            stdscr.move(curses.LINES-1, len(color) + 2)
            stdscr.refresh()
            move = stdscr.getstr(curses.LINES-1, len(color) + 2).decode('utf8')
        except KeyboardInterrupt:
            print('\nterminating ...')
            break
        except Exception as e:
            trace = traceback.format_exc()
            break
        if the_game:
            if move == '?':
                win.addstr('\n'+f"List of moves for game {the_game.ref}"+'\n')
                for m in the_game.moves:
                    if 'mv' in m.content:
                        win.addstr(f"  {m.content['n']} {m.content['mv']}"+'\n')
                continue
            if move == '!':
                chess_drawboard(str(the_game.logic))
                continue
            if not the_game.make_move(move):
                win.addstr(f"'{move}' - not your turn, or invalid move" + '\n')

    observer.stop()
    observer.join()
    
# ----------------------------------------------------------------------
if __name__ == '__main__':

    curses.wrapper(lambda stdscr: main(stdscr, sys.argv))
    if trace:
        print(trace)

# eof
