# fuzz_frame.py
# Seeds of fuzz_frame (src/fuzz/fuzz_frame.c): the header of a record of a Noise session (src/Cedar/NodeSourceGroup.c
# NodeFrameParse; SDN-87 #386). A record of frame version 0 is the VRF tag of its VRF, 4 bytes, and a packet. A record of
# frame version 1 begins with the VRF tag of no VRF, 0, then the frame version, the length of the options in words and two
# reserved bytes, then the options, each a header of 4 bytes (the type, whose high bit is the critical bit, the length of
# the data in words and two reserved bytes) and its data, then the data record of frame version 0. The option of the
# source group is of the type 1 with 16 bytes of data: the group ID, two reserved bytes, the tag set and the group
# generation of the sender.
#
# make_seeds.py runs make_seeds(h), h being make_seeds.py itself with write_seed and the packet helpers.

import struct


def option(typ, data=b''):
    # One option: its type, the length of its data in words, two reserved bytes, then the data
    return struct.pack('>BBH', typ, len(data) // 4, 0) + data


def group(group_id, tags, generation=1):
    # The option of the source group
    return option(0x01, struct.pack('>HHQI', group_id, 0, tags, generation))


def frame(options, version=1, words=None):
    # The header of a record of frame version 1 (or version) with the options, whose length is words when it is given
    words = len(options) // 4 if words is None else words
    return struct.pack('>IBBH', 0, version, words, 0) + options


def make_seeds(h):
    def seed(name, data):
        h.write_seed('fuzz_frame', name, data)

    # The data record of VRF 101: its VRF tag and an IPv4 header of 20 bytes
    record = struct.pack('>I', 101) + h.ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, b'', 1)[:20]

    # Frame version 0; frame version 1 with the source group, its smallest and its largest group ID and tag set
    seed('version_0.bin', record)
    seed('group.bin', frame(group(3, 0x4)) + record)
    seed('group_max.bin', frame(group(0xFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)) + record)
    seed('group_min.bin', frame(group(1, 0, 0)) + record)
    # Options that the node does not know: one whose critical bit is clear before the option of the source group, which
    # is skipped, two options of the source group, of which the last one counts, and a critical one, which drops the record
    seed('unknown_option.bin', frame(option(0x02) + group(7, 0x80)) + record)
    seed('two_groups.bin', frame(group(5, 0x10) + group(6, 0x20)) + record)
    seed('critical_option.bin', frame(option(0x82, b'\0' * 4)) + record)
    # The option of the source group with data of another length, which is not that option; no options at all
    seed('group_short.bin', frame(option(0x01, struct.pack('>HH', 3, 0))) + record)
    seed('no_options.bin', frame(b'') + record)
    # Records that the node drops: options that run past the record, an option whose data runs past the options, frame
    # version 2, and a header cut short
    seed('past_record.bin', frame(group(3, 0x4))[:12])
    seed('past_options.bin', frame(option(0x01, struct.pack('>HHQI', 3, 0, 0x4, 1)), words=2) + record)
    seed('version_2.bin', frame(b'', version=2) + record)
    seed('cut_header.bin', frame(b'')[:6])
    # The option of the source group, then an option whose data runs past the options: the record is dropped with no
    # claim, which a crash input of the fuzzer once found left behind
    seed('group_then_past_options.bin', frame(group(5, 0x10) + struct.pack('>BBH', 0x02, 4, 0), words=6) + record)
