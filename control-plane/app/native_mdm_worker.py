"""Customer-owned instance worker. No vendor customer-key upload/dispatch API.

Run explicitly in customer-controlled environment, NOT vendor application.
Uses the customer's own DB credentials/runtime and APNs private key local to
that instance. No production worker was deployed by building this module.
"""
import argparse
import json
import os
import time

from mdm.customer_apns import CustomerAPNsTransport
from .db import session_scope
from .native_mdm_config import factory, private_file
from .native_mdm import dispatch_customer_pushes, scan_identity_expiry


def main():
    parser=argparse.ArgumentParser(description="Customer-owned native MDM push/expiry worker")
    parser.add_argument("--once",action="store_true")
    args=parser.parse_args()
    config=json.loads(private_file(os.environ["KG_NATIVE_MDM_CONFIG"]).read_text())
    engine,runtime,_=factory()
    if len(runtime.topics)!=1:
        raise RuntimeError("customer worker requires exactly one tenant/topic")
    tenant,topic=next(iter(runtime.topics.items()))
    transport=CustomerAPNsTransport(
        certificate_file=config["customer_apns_certificate_file"],
        private_key_file=private_file(config["customer_apns_private_key_file"]),
        topic=topic, customer_instance_reference=config["customer_instance_reference"])
    try:
        while True:
            with session_scope(engine) as session:
                scan_identity_expiry(session,tenant_id=tenant)
                dispatch_customer_pushes(session,runtime,transport,tenant_id=tenant)
            if args.once:
                break
            time.sleep(15)  # dispatch itself obeys persisted bounded backoff
    finally:
        transport.close();engine.dispose()


if __name__=="__main__":
    main()
