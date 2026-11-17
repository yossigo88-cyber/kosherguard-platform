"""Explicit secret-store-backed native runtime factory, no startup side effects.

KG_NATIVE_MDM_CONFIG names a mode-0600 JSON file OUTSIDE the repository.
No defaults generate secrets/certificates or infer Apple business permission.
An optional ADE plugin must provide a validated live assignment lookup and
pre-verified signer pins. No plugin is bundled or automatically imported from
request input. An operator chooses it in this private configuration only.
"""
import importlib
import json
import os
import stat
from pathlib import Path

from cryptography import x509

from mdm.identity import load_identity, PKCS12Issuer, ProfileSigner, ProvisioningError
from .db import make_engine
from .native_mdm import EnrollmentRuntime
from .native_mdm_server import tls_context

REPO_ROOT = Path(__file__).resolve().parents[2]


def private_file(value):
    path = Path(value).expanduser().resolve(strict=True)
    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise ProvisioningError("private configuration/keys must be outside Git checkout")
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProvisioningError("private configuration/key file must be owner-only")
    return path


def factory():
    config = json.loads(private_file(os.environ["KG_NATIVE_MDM_CONFIG"]).read_text())
    # Passwords/encryption key are read from owner-only files, not CLI argv or
    # Git. Database URL comes from existing deployment secret environment.
    issuer_cert, issuer_key = load_identity(config["identity_ca_file"], private_file(config["identity_key_file"]))
    signer_cert, signer_key = load_identity(config["profile_signer_file"], private_file(config["profile_signer_key_file"]))
    chain = x509.load_pem_x509_certificates(Path(config["profile_chain_file"]).read_bytes())
    ade_verifier = None
    engine=make_engine(os.environ["KG_DATABASE_URL"])
    if config.get("ade"):
        from mdm.ade_identity import ADEIdentityVerifier
        from mdm.nanodep import NanoDEPClient, CurrentAssignmentLookup
        from mdm.identity import https_url
        from sqlalchemy import select
        from .models import MDMAppleInventory
        from .db import session_scope
        ade=config["ade"]
        def inventory_lookup(tenant_id,serial):
            with session_scope(engine) as session:
                return session.scalar(select(MDMAppleInventory.udid).where(
                    MDMAppleInventory.tenant_id==tenant_id,MDMAppleInventory.serial==serial))
        client=NanoDEPClient(https_url(ade["nanodep_url"]),private_file(ade["nanodep_api_key_file"]).read_text().strip())
        lookup=CurrentAssignmentLookup(client=client,tenant_id=ade["tenant_id"],
            dep_name=ade["dep_name"],profile_uuid=ade["profile_uuid"],inventory_lookup=inventory_lookup)
        ade_verifier=ADEIdentityVerifier(apple_root_file=ade["apple_root_file"],
            assigned_device_lookup=lookup,signer_pins={})
    elif config.get("ade_verifier_factory"):
        module, function = config["ade_verifier_factory"].split(":", 1)
        ade_verifier = getattr(importlib.import_module(module), function)()
    runtime = EnrollmentRuntime(issuer=PKCS12Issuer(issuer_cert, issuer_key),
        signer=ProfileSigner(signer_cert, signer_key, chain),
        signer_trust_file=config["profile_trust_file"], base_url=config["base_url"],
        organization=config["organization"],
        allowed_topics={int(k): v for k,v in config["tenant_topics"].items()},
        token_encryption_key=private_file(config["token_encryption_key_file"]).read_bytes().strip(),
        authorization_reference=config["authorization_reference"], ade_verifier=ade_verifier)
    context = tls_context(cert_file=config["tls_certificate_file"],
        key_file=private_file(config["tls_private_key_file"]),
        identity_ca_file=config["identity_ca_file"])
    return engine, runtime, context
