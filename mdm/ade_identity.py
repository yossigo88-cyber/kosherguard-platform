"""Strict classic ADE MachineInfo verifier.

Apple root trust alone is not treated as proof of device assignment or of
certificate purpose. Classic verifier requires a preverified per-device signer pin and a live
assignment lookup. The separate attended webflow may inspect a signer as
inventory before fresh guardian authorization, never for CMS-only delivery. No pins/roots or assignment credentials are bundled here.
"""
import tempfile
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .identity import ProvisioningError, verify_signed_profile


class ADEIdentityVerifier:
    def __init__(self, *, apple_root_file, assigned_device_lookup, signer_pins):
        if not callable(assigned_device_lookup):
            raise ProvisioningError("live assignment lookup and verified device signer pins required")
        self.apple_root_file = apple_root_file
        self.lookup = assigned_device_lookup
        self.pins = dict(signer_pins)

    def check_assignment(self, tenant_id, serial, udid):
        # Callback is trusted deployment integration, not request input. It
        # must query the tenant's assigned NanoDEP server and reject stale,
        # released, wrong-profile/server and provisional/ineligible devices.
        try:
            result = self.lookup(tenant_id, serial)
        except Exception as exc:
            raise ProvisioningError("current device assignment could not be verified") from exc
        if not isinstance(result, dict) or result.get("assigned") is not True or result.get("udid") != udid:
            raise ProvisioningError("device not currently assigned to this tenant/server")
        if (tenant_id, serial) not in self.pins:
            raise ProvisioningError("device MachineInfo signing identity has not been pinned")

    def verify(self, tenant_id, serial, udid, envelope):
        import plistlib
        self.check_assignment(tenant_id, serial, udid)
        info, signer = self.inspect(envelope)
        if signer != self.pins[(tenant_id, serial)]:
            raise ProvisioningError("unrecognized ADE MachineInfo signer")
        if info.get("SERIAL") != serial or info.get("UDID") != udid:
            raise ProvisioningError("MachineInfo identity mismatch")
        return info

    def inspect(self, envelope):
        """Verify Apple chain and actual single signer, NOT assignment/freshness.

        Used only before fresh attended guardian authorization. Never use
        inspection alone to issue identity/private profile bytes.
        """
        import plistlib
        raw = verify_signed_profile(envelope, self.apple_root_file)
        # Extract actual signer(s), not arbitrary extra certificates embedded
        # in a CMS bag. A pinned cert included as a non-signer proves nothing.
        with tempfile.TemporaryDirectory(prefix="kg-ade-") as directory:
            source, signers = Path(directory)/"in.der", Path(directory)/"signers.pem"
            source.write_bytes(envelope)
            result = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(source), "-CAfile", str(self.apple_root_file), "-purpose", "any", "-signer", str(signers), "-out", str(Path(directory)/"body")], capture_output=True, timeout=10)
            if result.returncode:
                raise ProvisioningError("invalid ADE CMS")
            certs = x509.load_pem_x509_certificates(signers.read_bytes())
        if len(certs) != 1:
            raise ProvisioningError("unrecognized ADE MachineInfo signer")
        try:
            info = plistlib.loads(raw)
        except Exception as exc:
            raise ProvisioningError("invalid MachineInfo plist") from exc
        if not isinstance(info, dict) or not isinstance(info.get("SERIAL"),str) or not isinstance(info.get("UDID"),str):
            raise ProvisioningError("MachineInfo identity missing")
        return info, certs[0].fingerprint(hashes.SHA256()).hex()
