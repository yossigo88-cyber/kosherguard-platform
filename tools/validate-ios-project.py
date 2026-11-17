#!/usr/bin/env python3
"""Static validation of ios/KosherGuard.xcodeproj and ios/Configuration.

Runs anywhere with python3 (Linux or macOS) - no Xcode needed. This is
the pre-flight check for the real Xcode build: it catches broken file
references, malformed plists, bundle-ID drift and leftover placeholders
BEFORE a Mac spends time compiling. It cannot catch Swift compile
errors; the GitHub Actions macOS job (ci/ios-compile-check.yml,
ios-compile-check.yml) or a local xcodebuild covers those.

Exit 0 = all checks passed (placeholders are reported, not failed -
they are expected until a real Apple team ID exists; use
--strict-placeholders to fail on them during the signing step).
"""

import plistlib
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IOS = ROOT / "ios"
PBX = IOS / "KosherGuard.xcodeproj" / "project.pbxproj"

errors = []
infos = []


def err(msg):
    errors.append(msg)


def info(msg):
    infos.append(msg)


def load_plist(path):
    # plistlib rejects XML comments only if malformed; Apple plists with
    # leading comments parse fine.
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def main():
    strict_placeholders = "--strict-placeholders" in sys.argv

    text = PBX.read_text()

    # ---- 1. PBXFileReference paths exist -------------------------------
    filerefs = {oid: (name, path) for oid, name, path in re.findall(
        r'(KG[0-9A-Za-z]+) /\* ([^*]+) \*/ = \{isa = PBXFileReference; '
        r'lastKnownFileType = [^;]+; path = "([^"]+)"; sourceTree = "<group>"; \};',
        text)}
    # same but with unquoted path (single-word paths may be unquoted)
    for oid, name, path in re.findall(
            r'(KG[0-9A-Za-z]+) /\* ([^*]+) \*/ = \{isa = PBXFileReference; '
            r'lastKnownFileType = [^;]+; path = ([A-Za-z0-9_./-]+); '
            r'sourceTree = "<group>"; \};', text):
        filerefs.setdefault(oid, (name, path))
    for oid, (name, path) in filerefs.items():
        if not (IOS / path).is_file():
            err(f"PBXFileReference {oid} ({name}) -> missing file ios/{path}")

    # ---- 2. PBXBuildFile -> PBXFileReference integrity ------------------
    buildfiles = re.findall(
        r'(KG[0-9A-Za-z]+) /\* ([^*]+) \*/ = \{isa = PBXBuildFile; '
        r'fileRef = (KG[0-9A-Za-z]+)', text)
    known_fileref_ids = set(re.findall(
        r'(KG[0-9A-Za-z]+) /\* [^*]+ \*/ = \{isa = PBXFileReference;', text))
    for bf_id, bf_name, ref in buildfiles:
        if ref not in known_fileref_ids:
            err(f"PBXBuildFile {bf_id} ({bf_name}) references unknown "
                f"fileRef {ref}")

    # ---- 3. Sources build phases reference known build files ------------
    known_buildfile_ids = {bf_id for bf_id, _, _ in buildfiles}
    for phase in re.findall(r'isa = PBXSourcesBuildPhase;.*?files = \((.*?)\);',
                            text, re.S):
        for fid in re.findall(r'(KG[0-9A-Za-z]+) /\*', phase):
            if fid not in known_buildfile_ids:
                err(f"Sources build phase references unknown build file {fid}")

    # ---- 4. Every swift file on disk is built by some target ------------
    built_paths = set()
    path_by_fileref = {oid: path for oid, (_, path) in filerefs.items()}
    for bf_id, bf_name, ref in buildfiles:
        p = path_by_fileref.get(ref)
        if p:
            built_paths.add(p)
    for swift in sorted(IOS.glob("Sources/**/*.swift")):
        rel = str(swift.relative_to(IOS))
        if rel not in built_paths:
            err(f"{rel} exists on disk but is in no target's Sources phase")

    # ---- 5. Build settings: INFOPLIST_FILE / entitlements exist --------
    for cfg_id, settings in re.findall(
            r'(KG[0-9A-Za-z]+) /\* (?:Debug|Release) \*/ = '
            r'\{isa = XCBuildConfiguration; buildSettings = \{ (.*?) \};', text):
        m = re.search(r'INFOPLIST_FILE = ([^;]+);', settings)
        if m and not (IOS / m.group(1)).is_file():
            err(f"XCBuildConfiguration {cfg_id}: missing {m.group(1)}")
        m = re.search(r'CODE_SIGN_ENTITLEMENTS = ([^;]+);', settings)
        if m and not (IOS / m.group(1)).is_file():
            err(f"XCBuildConfiguration {cfg_id}: missing {m.group(1)}")

    # ---- 6. Bundle IDs: unique, extensions nested under the app ID ------
    # Debug+Release list each ID twice; dedupe before checking.
    bundle_ids = sorted(set(re.findall(
        r'PRODUCT_BUNDLE_IDENTIFIER = ([^;]+);', text)))
    app_ids = [b for b in bundle_ids if b.count(".") == 2]
    if len(app_ids) != 1:
        err(f"expected exactly one 3-component app bundle ID, got {app_ids}")
    else:
        for b in bundle_ids:
            if b != app_ids[0] and not b.startswith(app_ids[0] + "."):
                err(f"extension bundle ID {b} is not under app ID {app_ids[0]}")
    if len(bundle_ids) != 5:
        err(f"expected 5 distinct bundle IDs (app + 4 extensions), "
            f"got {bundle_ids}")

    # ---- 7. Plists and entitlements parse -------------------------------
    parsed = {}
    for plist in sorted(IOS.glob("Configuration/*.plist")) + \
            sorted(IOS.glob("Configuration/*.entitlements")):
        try:
            parsed[plist.name] = load_plist(plist)
        except Exception as exc:  # noqa: BLE001 - report any parse failure
            err(f"{plist.name}: plist parse failed: {exc}")

    # ---- 8. Extension Info.plist extension-point declarations -----------
    for name, content in parsed.items():
        if not name.endswith("-Info.plist") or name == "App-Info.plist":
            continue
        has_nsext = "NSExtension" in content
        has_ex = "EXAppExtensionAttributes" in content
        if has_nsext == has_ex:
            err(f"{name}: must declare exactly one of NSExtension / "
                f"EXAppExtensionAttributes (NSExtension={has_nsext}, "
                f"EXAppExtensionAttributes={has_ex})")
        if has_nsext:
            pc = content["NSExtension"].get("NSExtensionPrincipalClass", "")
            if not pc:
                err(f"{name}: NSExtensionPrincipalClass missing")
    if "URLFilterExtension-Info.plist" in parsed:
        ex = parsed["URLFilterExtension-Info.plist"].get(
            "EXAppExtensionAttributes", {})
        if ex.get("EXExtensionPointIdentifier") != \
                "com.apple.networkextension.url-filter-control":
            err("URLFilterExtension-Info.plist: unexpected "
                f"EXExtensionPointIdentifier {ex.get('EXExtensionPointIdentifier')}")

    # ---- 9. App-group consistency across entitlements -------------------
    groups = {}
    for name, content in parsed.items():
        if name.endswith(".entitlements"):
            g = content.get("com.apple.security.application-groups", [])
            groups[name] = g
    all_groups = {tuple(v) for v in groups.values()}
    if len(all_groups) > 1:
        err(f"app-group identifiers differ across targets: {groups}")
    # URL Filter extension legitimately has no keychain-access-groups:
    # it never touches the session credential bundle.
    for name, content in parsed.items():
        if name.endswith(".entitlements") and name != "URLFilterExtension.entitlements":
            if "keychain-access-groups" not in content:
                info(f"{name}: no keychain-access-groups (verify intentional)")

    # ---- 10. Shared scheme parses ----------------------------------------
    scheme = IOS / "KosherGuard.xcodeproj" / "xcshareddata" / "xcschemes" / \
        "KosherGuard.xcscheme"
    if not scheme.is_file():
        err("shared scheme missing: " + str(scheme.relative_to(ROOT)))
    else:
        try:
            ET.parse(scheme)
        except ET.ParseError as exc:
            err(f"KosherGuard.xcscheme: XML parse failed: {exc}")

    # ---- 11. Placeholder sweep (report; fail only in strict mode) -------
    placeholder_hits = []
    for path in sorted(IOS.rglob("*")):
        if path.is_file() and path.suffix in {
                ".plist", ".entitlements", ".swift", ".pbxproj", ".md"}:
            body = path.read_text(errors="replace")
            for needle in ("TEAMIDPLACEHOLDER",
                           "group.com.kosherguard.shared",
                           "kosherguard.example.com",
                           "com.kosherguard.app"):
                if needle in body:
                    placeholder_hits.append(
                        f"{path.relative_to(ROOT)}: {needle}")
    for hit in placeholder_hits:
        (err if strict_placeholders else info)("placeholder pending: " + hit)

    # ---- report ----------------------------------------------------------
    for i in infos:
        print(f"INFO: {i}")
    for e in errors:
        print(f"FAIL: {e}")
    if errors:
        print(f"\nvalidate-ios-project: {len(errors)} FAILURE(S)")
        return 1
    print(f"\nvalidate-ios-project: all checks passed "
          f"({len(infos)} informational placeholder/note(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
