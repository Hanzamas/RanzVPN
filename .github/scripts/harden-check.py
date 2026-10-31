# harden-check.py
# CI checks for the hardened build variant (SEC-4 #282, ADR-0036). Standard library only, like the
# other scripts in this directory.
#
# Subcommands:
#   pe      --binary ranzguard.exe   the release variant has an empty import table and no section that
#                                    is both executable and writable (no RWX page baked into the image)
#   clean   --binary ranz-node.exe   the clean variant carries no obfuscation: it has an ordinary import
#                                    table and no VMProtect (.vmp*) section
#   markers --source ranzguard.c     the VMProtect markers wrap only the licence-gate and key-handling
#                                    routines, never main and never the whole file
#   safety  --source ranzguard.c     the source allocates no RWX page and never writes into ntdll
#
# Exit status is 0 when every assertion holds, 1 otherwise.

import argparse
import struct
import sys

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class Pe:
	# A minimal PE32+ reader: just the pieces the checks need (sections and the import directory).
	def __init__(self, path):
		with open(path, 'rb') as f:
			self.data = f.read()
		d = self.data
		if d[0:2] != b'MZ':
			raise ValueError('not a PE file (no MZ header): %s' % path)
		e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
		if d[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
			raise ValueError('not a PE file (no PE signature): %s' % path)
		file_header = e_lfanew + 4
		self.num_sections = struct.unpack_from('<H', d, file_header + 2)[0]
		size_opt = struct.unpack_from('<H', d, file_header + 16)[0]
		opt = file_header + 20
		magic = struct.unpack_from('<H', d, opt)[0]
		if magic != 0x20B:
			raise ValueError('not a PE32+ (x64) image (optional header magic 0x%X): %s' % (magic, path))
		# DataDirectory starts at optional-header offset 0x70 for PE32+; entry 1 is the import directory
		num_dirs = struct.unpack_from('<I', d, opt + 0x6C)[0]
		self.import_rva = 0
		self.import_size = 0
		if num_dirs >= 2:
			self.import_rva, self.import_size = struct.unpack_from('<II', d, opt + 0x70 + 8 * 1)
		self.sections = []
		sec = opt + size_opt
		for i in range(self.num_sections):
			base = sec + i * 40
			name = d[base:base + 8].rstrip(b'\x00')
			chars = struct.unpack_from('<I', d, base + 36)[0]
			self.sections.append((name, chars))

	def rwx_sections(self):
		out = []
		for name, chars in self.sections:
			if (chars & IMAGE_SCN_MEM_EXECUTE) and (chars & IMAGE_SCN_MEM_WRITE):
				out.append(name)
		return out

	def vmp_sections(self):
		return [name for name, _ in self.sections if name.lower().startswith(b'.vmp')]

	def has_imports(self):
		return self.import_rva != 0 and self.import_size != 0


def fail(msg):
	print('FAIL: %s' % msg)
	return False


def ok(msg):
	print('ok: %s' % msg)
	return True


def check_pe(path):
	pe = Pe(path)
	good = True
	if pe.has_imports():
		good = fail('%s has an import directory (RVA 0x%X, size %u); the release variant must resolve every API at run time (empty import table)' % (path, pe.import_rva, pe.import_size))
	else:
		ok('%s has an empty import table (dynamic API resolution)' % path)
	rwx = pe.rwx_sections()
	if rwx:
		good = fail('%s has a section that is executable and writable: %s (an RWX page trips HVCI and EDR)' % (path, b', '.join(rwx).decode('latin-1')))
	else:
		ok('%s has no executable-and-writable section' % path)
	return good


def check_clean(path):
	pe = Pe(path)
	good = True
	if pe.has_imports():
		ok('%s has an ordinary import table (not obfuscated)' % path)
	else:
		good = fail('%s has an empty import table; the clean variant is expected to import normally' % path)
	vmp = pe.vmp_sections()
	if vmp:
		good = fail('%s carries VMProtect sections %s; the clean variant must carry no obfuscation' % (path, b', '.join(vmp).decode('latin-1')))
	else:
		ok('%s carries no VMProtect section (no whole-binary packing)' % path)
	return good


def _function_span(text, signature):
	# The [start, end) character span of a function body, found by matching braces from the signature.
	# rfind, so the definition is taken, not an earlier extern declaration of the same signature.
	at = text.rfind(signature)
	if at < 0:
		return None
	brace = text.find('{', at)
	if brace < 0:
		return None
	depth = 0
	i = brace
	while i < len(text):
		c = text[i]
		if c == '{':
			depth += 1
		elif c == '}':
			depth -= 1
			if depth == 0:
				return (at, i + 1)
		i += 1
	return None


def check_markers(path):
	with open(path, 'r', encoding='latin-1') as f:
		text = f.read()
	good = True

	spans = {}
	for name, sig in (('licence_gate', 'int licence_gate(int suspicious)'), ('key_handling', 'u64 key_handling(int suspicious)')):
		span = _function_span(text, sig)
		if span is None:
			good = fail('could not find the body of %s in %s' % (name, path))
		else:
			spans[name] = span

	# Every use of a marker, excluding the two #define lines that introduce the macros
	uses = []
	for idx, line in enumerate(text.splitlines(), start=1):
		stripped = line.lstrip()
		if stripped.startswith('#define RANZ_VMP_BEGIN') or stripped.startswith('#define RANZ_VMP_END'):
			continue
		# Only the call form counts as a use; a prose mention in a comment does not
		if 'RANZ_VMP_BEGIN(' in line or 'RANZ_VMP_END(' in line:
			uses.append(idx)

	# The character offset where each line begins, to test containment in a function span
	offsets = []
	pos = 0
	for line in text.splitlines(keepends=True):
		offsets.append(pos)
		pos += len(line)

	begin_count = text.count('RANZ_VMP_BEGIN(') - text.count('#define RANZ_VMP_BEGIN')
	end_count = text.count('RANZ_VMP_END(') - text.count('#define RANZ_VMP_END')

	def inside_a_span(line_no):
		off = offsets[line_no - 1]
		for span in spans.values():
			if span[0] <= off < span[1]:
				return True
		return False

	stray = [ln for ln in uses if not inside_a_span(ln)]
	if stray:
		good = fail('VMProtect markers used outside the licence-gate and key-handling routines, at line(s) %s in %s (markers must not wrap main or the whole binary)' % (', '.join(str(x) for x in stray), path))
	else:
		ok('every VMProtect marker is inside the licence-gate or key-handling routine')

	if begin_count != 2 or end_count != 2:
		good = fail('expected one RANZ_VMP_BEGIN and one RANZ_VMP_END in each of the two routines (found %u begin, %u end)' % (begin_count, end_count))
	else:
		ok('exactly two begin and two end markers, one pair per protected routine')

	return good


def check_safety(path):
	with open(path, 'r', encoding='latin-1') as f:
		text = f.read()
	good = True
	forbidden = ['PAGE_EXECUTE_READWRITE', 'WriteProcessMemory', 'NtWriteVirtualMemory', 'NtProtectVirtualMemory', 'VirtualProtect', 'VirtualAllocEx']
	seen = [tok for tok in forbidden if tok in text]
	if seen:
		good = fail('%s names %s; the hardened binary must allocate no RWX page and never write into ntdll' % (path, ', '.join(seen)))
	else:
		ok('%s allocates no RWX page and writes into no module (none of %s)' % (path, ', '.join(forbidden)))
	return good


def main():
	ap = argparse.ArgumentParser(description='Hardened build variant checks (SEC-4 #282, ADR-0036)')
	sub = ap.add_subparsers(dest='cmd', required=True)
	for name in ('pe', 'clean'):
		p = sub.add_parser(name)
		p.add_argument('--binary', required=True)
	for name in ('markers', 'safety'):
		p = sub.add_parser(name)
		p.add_argument('--source', required=True)
	args = ap.parse_args()

	if args.cmd == 'pe':
		good = check_pe(args.binary)
	elif args.cmd == 'clean':
		good = check_clean(args.binary)
	elif args.cmd == 'markers':
		good = check_markers(args.source)
	elif args.cmd == 'safety':
		good = check_safety(args.source)
	else:
		good = False

	sys.exit(0 if good else 1)


if __name__ == '__main__':
	main()
