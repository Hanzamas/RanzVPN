"""Collect the files a local syntax-only compile check needs into one directory (used by devkit.yml).

Layout of the output directory:
  bin/clang-cl.exe              the CI compiler
  lib/clang/<ver>/include       its built-in headers (found by clang-cl relative to bin/)
  inc/<n>/                      the C header directories of INCLUDE (MSVC include, ucrt, um, shared)
  build/                        every header under the CI build directory (generated headers, OpenSSL)
  compile_commands.json         the CI compile commands
  devkit.json                   the CI paths to rewrite: workspace, build, compiler, include map
"""
import argparse, json, os, shutil, subprocess, sys

KEEP = ("include", "ucrt", "um", "shared")
HDR = (".h", ".hpp", ".hh", ".inc", ".inl", ".def")

ap = argparse.ArgumentParser()
ap.add_argument("--workspace", required=True)
ap.add_argument("--env", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()

env = {}
for line in open(a.env, encoding="utf-8", errors="replace"):
    if "=" in line:
        k, v = line.rstrip("\r\n").split("=", 1)
        env[k.strip()] = v.strip()
cc = env["CC_PATH"]
out = os.path.abspath(a.out)
os.makedirs(os.path.join(out, "bin"), exist_ok=True)
shutil.copy2(cc, os.path.join(out, "bin", "clang-cl.exe"))
for f in os.listdir(os.path.dirname(cc)):  # DLLs next to the compiler, if any
    if f.lower().endswith(".dll"):
        shutil.copy2(os.path.join(os.path.dirname(cc), f), os.path.join(out, "bin", f))

res = subprocess.run([cc, "-print-resource-dir"], capture_output=True, text=True).stdout.strip()
ver = os.path.basename(res)
shutil.copytree(os.path.join(res, "include"), os.path.join(out, "lib", "clang", ver, "include"))

inc_map = []
for i, d in enumerate(p for p in env["INCLUDE"].split(";") if p.strip()):
    d = d.rstrip("\\/")
    if os.path.basename(d).lower() not in KEEP or not os.path.isdir(d):
        continue
    if "atlmfc" in d.lower() or "auxiliary" in d.lower():
        continue
    dst = os.path.join(out, "inc", str(len(inc_map)))
    shutil.copytree(d, dst)
    inc_map.append({"runner": d, "local": "inc/" + str(len(inc_map))})

ws = os.path.abspath(a.workspace)
build = os.path.join(ws, "build")
n = 0
for root, dirs, files in os.walk(build):
    dirs[:] = [x for x in dirs if x not in ("CMakeFiles", ".cmake", "Testing", "vcpkg-bincache")]
    for f in files:
        if f.lower().endswith(HDR):
            src = os.path.join(root, f)
            dst = os.path.join(out, "build", os.path.relpath(src, build))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            n += 1
shutil.copy2(os.path.join(build, "compile_commands.json"), os.path.join(out, "compile_commands.json"))
json.dump({"workspace": ws, "build": build, "compiler": cc, "clang_version": ver, "include_map": inc_map},
          open(os.path.join(out, "devkit.json"), "w", encoding="utf-8"), indent=1)
print("compiler", cc, "| clang", ver, "| include dirs", [m["runner"] for m in inc_map], "| build headers", n)
sys.exit(0)
