# The vcpkg ports in the SBOM of the supply-chain workflow (ADR-0039 decision 4; SEC-1, #279).
#
# sbom-tool's component detection finds each port through the vcpkg.spdx.json document that vcpkg
# writes for it, but sbom-tool turns no vcpkg component into an SPDX package: the conversion of a
# detected component (ScannedComponentExtensions.ToSbomPackage of microsoft/sbom-tool) has no case
# for it, so the SBOM leaves the ports out. This adds the port package of each vcpkg.spdx.json that
# vcpkg wrote for the target triplet to the SBOM, as a dependency of its root package, and writes
# the SHA-256 file of the manifest again, as sbom-tool does: lowercase hex, no line break. The ports
# of the host triplet (vcpkg-cmake and the like) only build the others and are left out.
# .github/scripts/sbom-check.ps1 then checks that the SBOM names every port of vcpkg.json.

import argparse
import glob
import hashlib
import json
import os
import sys


def port_package(path):
    """The package of the port in the vcpkg.spdx.json document at path (SPDXRef-port)."""
    with open(path, encoding='utf-8') as f:
        doc = json.load(f)
    ports = [p for p in doc.get('packages', []) if p.get('SPDXID') == 'SPDXRef-port']
    if len(ports) != 1:
        sys.exit(f'{path}: {len(ports)} packages SPDXRef-port, not one')
    return ports[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sbom', required=True, help='the manifest.spdx.json of sbom-tool')
    ap.add_argument('--install-root', default=os.path.join('build', 'vcpkg_installed', 'x64-windows-static'),
                    help='the installed tree of the target triplet')
    args = ap.parse_args()

    with open(args.sbom, encoding='utf-8') as f:
        sbom = json.load(f)
    root = sbom['documentDescribes'][0]
    ids = {p['SPDXID'] for p in sbom['packages']}

    paths = sorted(glob.glob(os.path.join(args.install_root, 'share', '*', 'vcpkg.spdx.json')))
    if not paths:
        sys.exit(f'no vcpkg.spdx.json under {args.install_root}')

    for path in paths:
        port = port_package(path)
        spdx_id = 'SPDXRef-Package-vcpkg-' + port['name']
        if spdx_id in ids:
            sys.exit(f'{args.sbom}: {spdx_id} is there already')
        ids.add(spdx_id)
        # The fields of an SPDX 2.2 package; vcpkg writes SPDX 2.3, whose extra fields stay out
        sbom['packages'].append({
            'name': port['name'],
            'SPDXID': spdx_id,
            'versionInfo': port['versionInfo'],
            'downloadLocation': port.get('downloadLocation', 'NOASSERTION'),
            'filesAnalyzed': False,
            'licenseConcluded': port.get('licenseConcluded', 'NOASSERTION'),
            'licenseDeclared': port.get('licenseDeclared', 'NOASSERTION'),
            'copyrightText': port.get('copyrightText', 'NOASSERTION'),
            'supplier': 'NOASSERTION',
        })
        sbom['relationships'].append({
            'relationshipType': 'DEPENDS_ON',
            'relatedSpdxElement': spdx_id,
            'spdxElementId': root,
        })
        print(f'vcpkg {port["name"]} {port["versionInfo"]}: in the SBOM as {spdx_id}, from {path}')

    data = json.dumps(sbom, indent=2, ensure_ascii=False).encode('utf-8')
    with open(args.sbom, 'wb') as f:
        f.write(data)
    with open(args.sbom + '.sha256', 'w', encoding='ascii', newline='') as f:
        f.write(hashlib.sha256(data).hexdigest())
    print(f'{args.sbom}: {len(paths)} vcpkg ports added, {len(sbom["packages"])} packages')


if __name__ == '__main__':
    main()
