import httpx
import pytest

from mdm.customer_apns import CustomerAPNsTransport
from mdm.identity import ProvisioningError
from mdm.tests.pki_fixtures import make_ca, leaf, write_identity

TOPIC="com.apple.mgmt.test"


@pytest.fixture
def certfiles(tmp_path):
    ca,key=make_ca()
    cert,private=leaf(ca,key,uid=TOPIC)
    return write_identity(tmp_path,"customer",cert,private)


def test_actual_http2_request_contract_no_jwt_or_commands(certfiles):
    observed=[]
    def handle(request):
        observed.append(request)
        return httpx.Response(200,extensions={"http_version":b"HTTP/2"})
    def factory(**kwargs):
        assert kwargs["http2"] is True and kwargs["follow_redirects"] is False
        assert kwargs["verify"].verify_mode != 0
        return httpx.Client(transport=httpx.MockTransport(handle))
    transport=CustomerAPNsTransport(certificate_file=certfiles[0],private_key_file=certfiles[1],topic=TOPIC,customer_instance_reference="SYNTHETIC customer instance",client_factory=factory)
    result=transport.push(topic=TOPIC,token="ab"*32,push_magic="magic")
    assert result=={"accepted":True,"delivered":False,"applied":False}
    request=observed[0]
    assert request.method=="POST"
    assert str(request.url)=="https://api.push.apple.com/3/device/"+"ab"*32
    assert request.headers["apns-push-type"]=="mdm" and request.headers["apns-topic"]==TOPIC
    assert "authorization" not in request.headers and request.content==b'{"mdm":"magic"}'
    for kwargs in [dict(topic=TOPIC+"wrong",token="ab"*32,push_magic="magic"),dict(topic=TOPIC,token="../bad",push_magic="magic"),dict(topic=TOPIC,token="ab"*32,push_magic="")]:
        with pytest.raises(ProvisioningError):
            transport.push(**kwargs)
    transport.close()


@pytest.mark.parametrize("status,reason,classification",[(410,"Unregistered","bad_token"),(400,"DeviceTokenNotForTopic","bad_token"),(403,"BadCertificate","cert_problem"),(429,"TooManyRequests","retryable"),(503,"ServiceUnavailable","retryable")])
def test_apns_errors_not_delivery(certfiles,status,reason,classification):
    transport=CustomerAPNsTransport(certificate_file=certfiles[0],private_key_file=certfiles[1],topic=TOPIC,customer_instance_reference="TEST",client_factory=lambda **kw:httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(status,json={"reason":reason},extensions={"http_version":b"HTTP/2"}))))
    result=transport.push(topic=TOPIC,token="ab"*32,push_magic="magic")
    assert result=={"accepted":False,"classification":classification,"http_status":status}
    transport.close()


def test_topic_mismatch_and_http1_refused(certfiles):
    with pytest.raises(ProvisioningError):
        CustomerAPNsTransport(certificate_file=certfiles[0],private_key_file=certfiles[1],topic=TOPIC+"wrong",customer_instance_reference="TEST")
    with pytest.raises(ProvisioningError):
        CustomerAPNsTransport(certificate_file=certfiles[0],private_key_file=certfiles[1],topic=TOPIC,customer_instance_reference="")
    transport=CustomerAPNsTransport(certificate_file=certfiles[0],private_key_file=certfiles[1],topic=TOPIC,customer_instance_reference="TEST",client_factory=lambda **kw:httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(200))))
    with pytest.raises(ProvisioningError):
        transport.push(topic=TOPIC,token="ab"*32,push_magic="magic")
    transport.close()
