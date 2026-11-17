"""Customer-operated APNs MDM certificate transport.

Must run within the customer's accessible service instance. Vendor must not
receive customer's APNs private key (DPLA Attachment 10). This is NOT a
vendor-hosted key-upload service. No token/JWT APNs auth: MDM uses certificate
credentials. No Apple credential bundled; tests use synthetic certs/mocks.
"""
from __future__ import annotations

import json
import re
import ssl

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from .identity import load_identity, valid_cert, ProvisioningError
from .apns import classify_push_failure


class CustomerAPNsTransport:
    def __init__(self, *, certificate_file, private_key_file, topic,
                 customer_instance_reference, client_factory=httpx.Client):
        if not customer_instance_reference:
            raise ProvisioningError("customer-controlled instance reference required")
        cert, _ = load_identity(certificate_file, private_key_file)
        uids = cert.subject.get_attributes_for_oid(NameOID.USER_ID)
        if len(uids) != 1 or uids[0].value != topic or not topic.startswith("com.apple.mgmt."):
            raise ProvisioningError("APNs certificate UID/topic mismatch")
        # Portal MDM push certs are production only. No sandbox/JWT option.
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate_file, private_key_file)
        self.cert, self.topic = cert, topic
        self.client = client_factory(http2=True, verify=context, timeout=10,
                                     follow_redirects=False)

    def close(self):
        self.client.close()

    def push(self, *, topic, token, push_magic):
        valid_cert(self.cert)
        if topic != self.topic or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32,512}", token) or len(token) % 2:
            raise ProvisioningError("invalid customer push target")
        if not isinstance(push_magic, str) or not 1 <= len(push_magic) <= 1024:
            raise ProvisioningError("invalid PushMagic")
        # HTTP/2 with cert auth; no Authorization header. Request body is ONLY
        # wake magic, never a command, policy, UDID or customer information.
        response = self.client.post("https://api.push.apple.com/3/device/"+token,
                headers={"apns-topic": topic, "apns-push-type": "mdm",
                         "apns-priority": "10", "apns-expiration": "0"},
                json={"mdm": push_magic})
        if response.http_version != "HTTP/2":
            raise ProvisioningError("APNs did not negotiate HTTP/2")
        if response.status_code == 200:
            return {"accepted": True, "delivered": False, "applied": False}
        try:
            reason = response.json().get("reason", "Unknown")
        except (ValueError, AttributeError):
            reason = "Unknown"
        # No response body echo: may include attacker-controlled strings.
        return {"accepted": False, "classification": classify_push_failure(reason).value,
                "http_status": response.status_code}
