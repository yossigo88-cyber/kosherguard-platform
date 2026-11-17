"""Synthetic PKI fixtures. Never an Apple certificate; generated in tmp only."""
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca():
    k = key()
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC TEST CA - NOT APPLE")])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .sign(k, hashes.SHA256()))
    return c, k


def leaf(ca, cakey, name="test", *, client=True, server=False, expired=False, uid=None):
    k = key()
    now = datetime.now(timezone.utc)
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, name)]
    if uid:
        attributes.append(x509.NameAttribute(NameOID.USER_ID, uid))
    b = (x509.CertificateBuilder().subject_name(x509.Name(attributes)).issuer_name(ca.subject)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now-timedelta(days=3)).not_valid_after(now+timedelta(days=-1 if expired else 90))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True))
    purposes = []
    if client:
        purposes.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if server:
        purposes.append(ExtendedKeyUsageOID.SERVER_AUTH)
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    if purposes:
        b = b.add_extension(x509.ExtendedKeyUsage(purposes), critical=False)
    return b.sign(cakey, hashes.SHA256()), k


def write_identity(tmp_path, stem, cert, key):
    c, k = tmp_path/(stem+".pem"), tmp_path/(stem+".key")
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    k.chmod(0o600)
    return str(c), str(k)
