#!/usr/bin/env python3

import time
import sys
import os

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--play', action='store_true')
parser.add_argument('-f', '--fast', action='store_true')
parser.add_argument('filename', nargs='?', default=None)
args = parser.parse_args()

sys.stdout = open('/dev/stdout', 'wb')

if args.play: # playback mode
    if args.filename:
        inputfile = open(args.filename, 'rb')
    else:
        inputfile = sys.stdin.buffer

    while not inputfile.closed:
        stamp = inputfile.read(17).decode('ascii')
        if len(stamp) < 17:
            break
        ms, length = [int(s) for s in stamp.split(',')]

        recorded = inputfile.read(length)

        if not args.fast:
            time.sleep(ms / 1e3)

        sys.stdout.write(recorded)
        sys.stdout.flush()
    sys.exit(0)


prev_t = time.monotonic() * 1e3

if args.filename:
    outfile = open(args.filename, 'wb')
else:
    outfile = sys.stdout.buffer

while not sys.stdin.buffer.closed:
    in_str = sys.stdin.buffer.read1()
    if len(in_str) == 0:
        break

    next_t = time.monotonic() * 1e3 # milli-second granularity should be fine
    stamp = "{:08d},{:08d}".format(int(next_t - prev_t), len(in_str)).encode('ascii')

    outfile.write(stamp)
    outfile.write(in_str)
    outfile.flush()

    if args.filename: # tee mode
        sys.stdout.buffer.write(in_str)
        sys.stdout.buffer.flush()

    prev_t = next_t


