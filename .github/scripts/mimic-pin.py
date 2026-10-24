# The reminder to bump the browser parrots of the mimicry sidecar (CORE-P2-1, #85, ADR-0023).
#
# `ranz mimic` sends the ClientHello of a browser, which uTLS has as a parrot for each browser version.
# go.mod pins uTLS, and controller/internal/mimic/fingerprint.go names the Chrome version of the parrot
# (chromiumParrotMajor: Edge is Chromium and sends the ClientHello of Chrome) and the day on which a
# maintainer last checked the parrots against the browsers and the releases of uTLS (parrotReviewed).
# A browser makes a major release every four weeks, so a parrot goes stale; this script fails when it
# has, and the workflow mimic-pin.yml runs it on a schedule, so that the failure is the reminder.
#
# The check fails when:
# - parrotReviewed is more than MAX_REVIEW_AGE_DAYS back (six weeks: a release comes every four, and a
#   bump takes time), or is a day that has not come;
# - online: uTLS has a newer release than go.mod pins, or its newest Chrome parrot is newer than
#   chromiumParrotMajor.
# It only says so, and does not fail, when the stable Chrome is more majors ahead than the newest
# parrot of uTLS: nothing can be bumped then, and the day of the review is what is left to move.
# A bump changes go.mod and go.sum, the version in fingerprint_test.go (utlsPin) and
# chromiumParrotMajor if the parrot moved, and sets parrotReviewed to the day of the review.
#
# Usage:
#   python mimic-pin.py check [--root DIR] [--offline]   the pin against today, and without --offline
#                                                         against the releases of uTLS and Chrome
#   python mimic-pin.py selftest                          the tests of this script, which need no network
#
# Standard library only.

import argparse
import datetime
import json
import os
import re
import sys
import tempfile
import urllib.request

FINGERPRINT = 'controller/internal/mimic/fingerprint.go'
GOMOD = 'go.mod'
MAX_REVIEW_AGE_DAYS = 42
UTLS = 'refraction-networking/utls'
CHROME_VERSIONS = 'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json'


def read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def read_pin(root):
    # (the version of uTLS in go.mod, chromiumParrotMajor, parrotReviewed)
    gomod = read(os.path.join(root, GOMOD))
    m = re.search(r'^\s*github\.com/refraction-networking/utls\s+(v\S+)\s*$', gomod, re.M)
    if not m:
        raise SystemExit('%s does not require github.com/refraction-networking/utls' % GOMOD)
    fingerprint = read(os.path.join(root, FINGERPRINT))
    major = re.search(r'chromiumParrotMajor\s*=\s*(\d+)', fingerprint)
    reviewed = re.search(r'parrotReviewed\s*=\s*"(\d{4}-\d{2}-\d{2})"', fingerprint)
    if not major or not reviewed:
        raise SystemExit('%s has no chromiumParrotMajor or no parrotReviewed' % FINGERPRINT)
    return m.group(1), int(major.group(1)), datetime.date.fromisoformat(reviewed.group(1))


def version_key(tag):
    return tuple(int(n) for n in re.findall(r'\d+', tag))


def newest_chrome_parrot(common_go):
    # The newest HelloChrome_<major> that u_common.go of uTLS defines
    majors = [int(n) for n in re.findall(r'^\s*HelloChrome_(\d+)\s*=\s*ClientHelloID\{', common_go, re.M)]
    return max(majors) if majors else None


def evaluate(pin, today, latest_utls=None, newest_parrot=None, chrome_stable=None):
    # The findings, as (level, message) with the level error, warning or notice; no error is a pass
    utls, major, reviewed = pin
    out = []
    age = (today - reviewed).days
    if age < 0:
        out.append(('error', 'parrotReviewed is %s, a day that has not come' % reviewed))
    elif age > MAX_REVIEW_AGE_DAYS:
        out.append(('error', 'the parrots were last reviewed on %s, %d days ago, more than the %d days between two '
                             'browser releases and a bump: check uTLS for a newer parrot, bump it if there is one, '
                             'and set parrotReviewed in %s to today' % (reviewed, age, MAX_REVIEW_AGE_DAYS, FINGERPRINT)))
    if latest_utls and version_key(latest_utls) > version_key(utls):
        out.append(('error', 'uTLS %s is out and go.mod pins %s: bump it (go.mod, go.sum, utlsPin in '
                             'fingerprint_test.go) and set parrotReviewed' % (latest_utls, utls)))
    if newest_parrot and newest_parrot > major:
        out.append(('error', 'uTLS has a parrot of Chrome %d and the sidecar uses Chrome %d: set chromiumParrot and '
                             'chromiumParrotMajor in %s' % (newest_parrot, major, FINGERPRINT)))
    if chrome_stable and chrome_stable > (newest_parrot or major):
        out.append(('notice', 'the stable Chrome is %d and the newest parrot is Chrome %d: uTLS has no newer one yet'
                    % (chrome_stable, newest_parrot or major)))
    return out


def fetch(url, token=None):
    req = urllib.request.Request(url, headers={'User-Agent': 'ranz-mimic-pin'})
    if token and url.startswith('https://api.github.com/'):
        req.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(req, timeout=30) as res:
        return res.read().decode('utf-8')


def online(pin, out):
    # What the network knows: the latest release of uTLS and its newest parrot, and the stable Chrome. A
    # lookup that fails is a warning: the network is not the pin's fault.
    token = os.environ.get('GITHUB_TOKEN')
    latest = newest = chrome = None
    try:
        latest = json.loads(fetch('https://api.github.com/repos/%s/releases/latest' % UTLS, token))['tag_name']
        newest = newest_chrome_parrot(fetch('https://raw.githubusercontent.com/%s/%s/u_common.go' % (UTLS, latest)))
    except Exception as e:  # noqa: BLE001 - any failure of the lookup is the same warning
        out.append(('warning', 'the releases of uTLS could not be read: %s' % e))
    try:
        chrome = int(json.loads(fetch(CHROME_VERSIONS))['channels']['Stable']['version'].split('.')[0])
    except Exception as e:  # noqa: BLE001
        out.append(('warning', 'the stable Chrome could not be read: %s' % e))
    return latest, newest, chrome


def check(root, offline):
    pin = read_pin(root)
    print('uTLS %s, parrot Chrome %d, reviewed %s' % pin)
    findings = []
    latest = newest = chrome = None
    if not offline:
        latest, newest, chrome = online(pin, findings)
        print('latest uTLS %s, its newest parrot Chrome %s, the stable Chrome %s' % (latest, newest, chrome))
    findings += evaluate(pin, datetime.date.today(), latest, newest, chrome)
    failed = False
    for level, message in findings:
        failed = failed or level == 'error'
        print('::%s::%s' % (level, message) if os.environ.get('GITHUB_ACTIONS') else '%s: %s' % (level, message))
    if failed:
        print('the browser parrots of ranz mimic need a look (%s)' % FINGERPRINT)
        return 1
    print('the browser parrots of ranz mimic are pinned and were reviewed in time')
    return 0


def selftest():
    pin = ('v1.8.2', 133, datetime.date(2026, 10, 24))
    errors = lambda findings: [m for level, m in findings if level == 'error']

    assert evaluate(pin, datetime.date(2026, 10, 24)) == []
    assert evaluate(pin, datetime.date(2026, 12, 5)) == [], 'exactly 42 days is still in time'
    assert 'last reviewed' in errors(evaluate(pin, datetime.date(2026, 12, 6)))[0]
    assert 'has not come' in errors(evaluate(pin, datetime.date(2026, 10, 1)))[0]

    today = datetime.date(2026, 10, 25)
    assert errors(evaluate(pin, today, 'v1.8.2', 133)) == []
    assert errors(evaluate(pin, today, 'v1.7.9', 130)) == [], 'an older release is no reason'
    assert 'v1.9.0' in errors(evaluate(pin, today, 'v1.9.0', 133))[0]
    assert 'v1.10.0' in errors(evaluate(pin, today, 'v1.10.0', 133))[0], 'versions compare as numbers'
    assert 'Chrome 135' in errors(evaluate(pin, today, 'v1.8.2', 135))[0]
    assert len(errors(evaluate(pin, datetime.date(2027, 1, 1), 'v1.9.0', 135))) == 3

    news = evaluate(pin, today, 'v1.8.2', 133, 150)
    assert errors(news) == [] and news[0][0] == 'notice' and '150' in news[0][1]
    assert evaluate(pin, today, 'v1.8.2', 133, 133) == []

    sample = ('\tHelloChrome_Auto        = HelloChrome_133\n\tHelloChrome_58          = ClientHelloID{helloChrome, "58", nil, nil}\n'
              '\tHelloChrome_106_Shuffle = ClientHelloID{helloChrome, "106", nil, nil}\n'
              '\tHelloChrome_133 = ClientHelloID{helloChrome, "133", nil, nil}\n\tHelloFirefox_120 = ClientHelloID{helloFirefox, "120", nil, nil}\n')
    assert newest_chrome_parrot(sample) == 133
    assert newest_chrome_parrot('') is None
    assert version_key('v1.10.0') > version_key('v1.9.9')

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, os.path.dirname(FINGERPRINT)))
        with open(os.path.join(root, GOMOD), 'w', encoding='utf-8') as f:
            f.write('module x\n\nrequire (\n\tgithub.com/refraction-networking/utls v1.8.2\n\tgolang.org/x/sys v0.1.0 // indirect\n)\n')
        with open(os.path.join(root, FINGERPRINT), 'w', encoding='utf-8') as f:
            f.write('const (\n\tchromiumParrotMajor = 133\n\tparrotReviewed      = "2026-10-24"\n)\n')
        assert read_pin(root) == pin
        assert check(root, offline=True) in (0, 1)
    print('mimic-pin selftest: ok')
    return 0


def main():
    ap = argparse.ArgumentParser(description='The reminder to bump the browser parrots of ranz mimic')
    ap.add_argument('mode', choices=['check', 'selftest'])
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    ap.add_argument('--offline', action='store_true', help='check: do not ask the network')
    args = ap.parse_args()
    if args.mode == 'selftest':
        return selftest()
    return check(args.root, args.offline)


if __name__ == '__main__':
    sys.exit(main())
