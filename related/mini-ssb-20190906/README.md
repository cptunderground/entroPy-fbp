# Quick test of mini-ssb (README.md)

## 1) Required Python libraries

Load all of the following libraries with ```pip3 install XYZ```

```text
cbor2
Chessnut
PyNaCl
toposort
watchdog
```

## 2) Create and populate some log files (`log-A.pcap` etc)

```bash
% ./lib_core.py -dump
```
This generates secret key pairs for three users A, B and C, and adds
some events in their logs (chat messages, first chess moves, user
directory entries). Use this command to reset the log content after
having played with the two demos below.

You can reload these settings with
```bash
% ./lib_core.py -load
```

or run the tests with transient key pairs and logs (which are
then only kept in memory):
```bash
% ./lib_core.py
```


## 3) Chat among three users (using different consoles)

The chat application runs over a private subchannel so that all
corresponding log entries are encrypted. Using the `./lib_core.py
-dump` command, three users A, B and C are created which have received
the credentials of a shared subchannel (hkey and dkey).

Running the demo app requires two parameters. The first is the
_owner_ of the main log who is entitled to write to that log; the
second is a comma-separated list of other logs to read from (= 'whom
to follow').

In the following example, A and C both follow B, B follows both of
them. This means that A cannot see what C writes, and vice versa, but
B sees both and is seen by both.

```bash
term1% ./demo-chat A B
term2% ./demo-chat B A,C
term3% ./demo-chat C B
```

Note that the three client programs communicate via the log files.


## 4) Play chess

See the explanation above for the parameters. This demo application
uses direct encrypted messages instead of a private subchannel i.e.,
the messages are encrypted such that only the other peer (and the
sender) can read them.

```bash
term1% ./demo-chess A B
term2% ./demo-chess B A
```

and some moves you can try:
```text
black: e7e5
white: g1f3
black: b8c6
white: f1b5
etc
```

---
