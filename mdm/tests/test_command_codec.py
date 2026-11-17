import base64
import plistlib
import pytest
from mdm.command_codec import encode_command
from mdm.identity import ProvisioningError


def test_profile_dictionary_converts_to_apple_data():
    p={"PayloadType":"Configuration","PayloadContent":[]}
    c=encode_command("InstallProfile",{"profile":p})
    assert c["RequestType"]=="InstallProfile" and plistlib.loads(c["Payload"])==p
    assert encode_command("InstallProfile",{"Payload":base64.b64encode(b"cms").decode()})["Payload"]==b"cms"
    assert encode_command("RemoveProfile",{"Identifier":"com.example.profile"})["Identifier"]=="com.example.profile"


@pytest.mark.parametrize("name,payload",[("InstallProfile",{}),("InstallProfile",{"Payload":"??"}),("ProfileList",{"RequestType":"EraseDevice"}),("DeclarativeManagement",{}),("RemoveProfile",{}),("DeviceInformation",{"Queries":"UDID"})])
def test_invalid_command_shapes_reject(name,payload):
    with pytest.raises(ProvisioningError):encode_command(name,payload)


def test_install_application_with_managed_configuration():
    c=encode_command("InstallApplication",{"ITunesStoreID":123456789,"Options":{"NotManaged":False},"Configuration":{"controlPlaneBaseURL":"https://cp.example.test","deviceID":7}})
    assert c["RequestType"]=="InstallApplication" and c["ITunesStoreID"]==123456789
    assert c["Configuration"]=={"controlPlaneBaseURL":"https://cp.example.test","deviceID":7}
    # The wire form must survive plist serialization exactly - the
    # device receives plistlib.dumps({"Command": c}).
    assert plistlib.loads(plistlib.dumps(c))==c


def test_remove_application_roundtrip():
    c=encode_command("RemoveApplication",{"Identifier":"com.kosherguard.app"})
    assert c["RequestType"]=="RemoveApplication" and c["Identifier"]=="com.kosherguard.app"
    assert plistlib.loads(plistlib.dumps(c))==c


@pytest.mark.parametrize("payload",[
    {},                                              # no store id
    {"ITunesStoreID":0},
    {"ITunesStoreID":-5},
    {"ITunesStoreID":True},                          # bool is not a store id
    {"ITunesStoreID":"123"},                        # string is not a store id
    {"ITunesStoreID":1,"Options":"yes"},            # Options must be a dict
    {"ITunesStoreID":1,"Configuration":[1]},        # Configuration must be a dict
    {"ITunesStoreID":1,"Configuration":{"k":None}},# plist cannot carry null
    {"ITunesStoreID":1,"Surprise":{}},               # unknown key
])
def test_install_application_invalid_shapes_reject(payload):
    with pytest.raises(ProvisioningError):encode_command("InstallApplication",payload)


@pytest.mark.parametrize("payload",[{},{"Identifier":""},{"Identifier":7},{"Identifier":"com.example.app","Extra":1}])
def test_remove_application_invalid_shapes_reject(payload):
    with pytest.raises(ProvisioningError):encode_command("RemoveApplication",payload)
