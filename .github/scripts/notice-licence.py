# The NOTICE check of ONE-4 (#313): the licence text of a component that ranz carries as a Payload is
# in the NOTICE (controller/cmd/ranz/NOTICE) word for word. It takes the NOTICE and the licence file
# of the component's pinned release, and compares their words, not their line breaks or their
# spacing, as TestNoticeHasTheGoBGPLicence (controller/cmd/ranz) does for the GoBGP that go.mod pins.
# So a new version of the component, which may change its licence text, fails until the NOTICE follows.
#
# Usage: python notice-licence.py NOTICE LICENSE    exit status 1 when the NOTICE lacks the licence
#
# Standard library only.

import sys

# How many words of the licence must match for the difference to be reported there
RUN = 10


def words(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read().split()


def first_difference(notice, licence):
    # The NOTICE has a heading of its own before the licence text, so the two are aligned at the
    # first run of RUN words that they share
    for start in range(len(notice)):
        n = 0
        while n < len(licence) and start + n < len(notice) and notice[start + n] == licence[n]:
            n += 1
        if n >= RUN:
            got = repr(notice[start + n]) if start + n < len(notice) else 'the end of the NOTICE'
            return f'word {n + 1} of the licence is {licence[n]!r}, and the NOTICE has {got} there'
    return f'the NOTICE has no run of {RUN} words of the licence'


def main(argv):
    if len(argv) != 3:
        print('usage: notice-licence.py NOTICE LICENSE', file=sys.stderr)
        return 2
    notice, licence = words(argv[1]), words(argv[2])
    if not licence:
        print(f'{argv[2]} holds no words', file=sys.stderr)
        return 1
    for start in range(len(notice) - len(licence) + 1):
        if notice[start:start + len(licence)] == licence:
            print(f'{argv[1]} holds the {len(licence)} words of {argv[2]}')
            return 0
    print(f'{argv[1]} does not hold the licence text of {argv[2]} word for word: {first_difference(notice, licence)}',
          file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
