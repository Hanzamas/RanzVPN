# fuzz_control.py
# Seeds of fuzz_control (src/fuzz/fuzz_control.c): the control stream of a node (src/Core/Control.c, SDN-3 #179). They are
# the control messages of the controller tests: the conformance tests of controller/internal/controller and the cluster
# tests of controller/cluster_test.go write every frame that their simulated nodes sent and received into the directory
# that RANZ_CONTROL_WIRE names, one file per frame (<test>-<node>-<index>-<recv|sent>.bin), and these are the files that
# tests/control/nanopb_roundtrip.c decodes in CI (the nanopb round trip of ranz.yml). Each message is a seed of its own
# (wire-<file>), which fuzz_control reads as one message; and the messages that one simulated node received, in their
# order, make one stream (stream-<test>-<node>.bin), each the size of its message in 4 bytes (big-endian) and the message,
# as the controller sends them, so that the deltas of a stream apply to the state before them. A seed whose bytes an
# earlier one has is left out.
#
# The seeds of src/fuzz/corpus/fuzz_control are the frames of the tests of 2026-10-27 (AUD1-DT-12 #460), written with
#   RANZ_CONTROL_WIRE=<dir> RQLITED=<rqlited of the pinned rqlite> go test -count=1 ./controller/internal/controller ./controller
#   RANZ_CONTROL_WIRE=<dir> python -I src/fuzz/make_seeds.py
# Without RANZ_CONTROL_WIRE this file writes nothing, and the seeds stay as they are.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed.

import hashlib
import os
import re
import struct


def make_seeds(h):
    directory = os.environ.get('RANZ_CONTROL_WIRE')
    if not directory or not os.path.isdir(directory):
        return

    seen = set()
    streams = {}

    def seed(name, data):
        digest = hashlib.sha256(data).digest()
        if digest not in seen:
            seen.add(digest)
            h.write_seed('fuzz_control', name, data)

    for name in sorted(os.listdir(directory)):
        m = re.match(r'^(.+)-(\d+)-(recv|sent)\.bin$', name)
        if m is None:
            continue
        with open(os.path.join(directory, name), 'rb') as f:
            data = f.read()
        seed('wire-' + name, data)
        if m.group(3) == 'recv':
            streams.setdefault(m.group(1), []).append((int(m.group(2)), data))

    for key in sorted(streams):
        frames = sorted(streams[key])
        seed('stream-%s.bin' % key, b''.join(struct.pack('>I', len(data)) + data for _, data in frames))
