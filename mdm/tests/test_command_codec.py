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
