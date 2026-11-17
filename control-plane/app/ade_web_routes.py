"""Stable attended ADE web flow. Same origin as final private profile.

No account-driven enrollment, unauthenticated CMS-only key delivery, or
background automatic re-enrollment is provided. This UI uses the existing
rate-limited MFA login then a same-session/CSRF guarded explicit decision.
"""
import base64
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, StrictBool, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import ade_web, native_mdm as n
from .models import MDMAppleInventory
from .staff_routes import fresh_check
from mdm.identity import ProvisioningError

COOKIE="kg_ade_ceremony"
ASSETS=Path(__file__).parent


class InventoryBody(BaseModel):
    serial:str=Field(min_length=1,max_length=120)
    udid:str=Field(min_length=8,max_length=120)
    totp_code:str
    confirm:str


class FreshBody(BaseModel):
    totp_code:str
    confirm:str


class ApprovalBody(BaseModel):
    device_id:int
    restart:StrictBool=False


class Admission:
    def __init__(self):
        self.lock=threading.Lock();self.ips=OrderedDict()
    def accept(self,ip):
        with self.lock:
            now=time.monotonic()
            if ip not in self.ips:
                if len(self.ips)>=1024:self.ips.popitem(last=False)
                self.ips[ip]=deque()
            q=self.ips[ip]
            self.ips.move_to_end(ip)
            while q and q[0]<=now-60:q.popleft()
            if len(q)>=10:return False
            q.append(now);return True


def register(app,*,runtime,error,current_user,db_session,require_guardian,require_csrf_header,settings):
    admission=Admission()

    def private(response):
        response.headers.update({"Cache-Control":"no-store, private","Pragma":"no-cache",
            "Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff",
            "Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})
        return response

    @app.get("/ade/enroll")
    def start(request:Request,session=Depends(db_session)):
        if not admission.accept(request.client.host if request.client else "unknown"):
            return error(429,"ADE enrollment rate limit")
        if runtime is None or runtime.ade_verifier is None:
            return error(503,"attended ADE is not configured")
        try:
            header=request.headers.get("x-apple-aspen-deviceinfo","")
            if not 1<=len(header)<=90000:raise ValueError()
            envelope=base64.b64decode(header,validate=True)
            state=ade_web.begin(session,runtime,envelope)
            session.commit()
        except n.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        except (ValueError,ProvisioningError):
            session.rollback();return error(403,"invalid signed device information")
        response=HTMLResponse((ASSETS/"ade_enroll.html").read_text())
        response.set_cookie(COOKIE,state,httponly=True,secure=settings.secure_cookies,samesite="strict",max_age=600,path="/")
        return private(response)

    @app.get("/ade/enroll.js")
    def script():
        return private(Response((ASSETS/"ade_enroll.js").read_bytes(),media_type="application/javascript"))

    @app.post("/api/mdm/devices/{device_id}/apple-inventory",dependencies=[Depends(require_csrf_header)])
    def inventory(device_id:int,body:InventoryBody,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        denied=fresh_check(error,user,body.totp_code,body.confirm,"approve-device-inventory")
        if denied is not None:return denied
        try:
            ade_web.approve_inventory(session,tenant_id=user.tenant_id,device_id=device_id,
                serial=body.serial,udid=body.udid,actor_user_id=user.id)
            session.commit()
        except n.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        except IntegrityError:
            session.rollback();return error(409,"inventory already assigned")
        return {"approved":True,"hardware_attested":False}

    @app.get("/api/mdm/ade/ceremony")
    def ceremony(request:Request,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        if runtime is None:return error(503,"ADE is not configured")
        try:
            data=ade_web._ceremony(session,runtime,request.cookies.get(COOKIE,""))
            ade_web._fresh_session(session,request.cookies.get("kg_session"),user.id,data["started_at"])
            row=session.scalar(select(MDMAppleInventory).where(MDMAppleInventory.tenant_id==user.tenant_id,MDMAppleInventory.serial==data["serial"],MDMAppleInventory.udid==data["udid"]))
            if row is None:return error(403,"signed device does not match approved inventory")
            return {"device_id":row.device_id,"serial":row.serial,"udid":row.udid,"proof":"attended guardian authorization, not fresh hardware attestation"}
        except n.TransportError as exc:return error(exc.status,str(exc))

    @app.post("/api/mdm/ade/authorize",dependencies=[Depends(require_csrf_header)])
    def authorize(request:Request,body:ApprovalBody,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        if runtime is None:return error(503,"ADE is not configured")
        try:
            nonce=ade_web.authorize(session,runtime,state=request.cookies.get(COOKIE,""),session_token=request.cookies.get("kg_session"),
                user=user,device_id=body.device_id,restart=body.restart)
            session.commit()
            return {"profile_path":"/api/mdm/ade/profile/"+nonce,"one_use":True,"attended_only":True}
        except n.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        except (ProvisioningError,IntegrityError):
            session.rollback();return error(409,"ADE assignment or identity conflict")

    @app.get("/api/mdm/ade/profile/{nonce}")
    def profile(nonce:str,request:Request,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        if runtime is None:return error(503,"ADE is not configured")
        try:
            result=ade_web.deliver(session,runtime,state=request.cookies.get(COOKIE,""),session_token=request.cookies.get("kg_session"),user=user,nonce=nonce)
            session.commit()
            response=Response(result,media_type="application/x-apple-aspen-config")
            response.headers["Content-Disposition"]='attachment; filename="KosherGuard-enrollment.mobileconfig"'
            response.delete_cookie(COOKIE,path="/")
            return private(response)
        except n.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        except (ProvisioningError,IntegrityError,ValueError):
            session.rollback();return error(409,"ADE profile verification or assignment failed")

    @app.patch("/api/mdm/devices/{device_id}/apple-inventory",dependencies=[Depends(require_csrf_header)])
    def correct_inventory(device_id:int,body:InventoryBody,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        denied=fresh_check(error,user,body.totp_code,body.confirm,"correct-device-inventory")
        if denied is not None:return denied
        try:
            ade_web.correct_inventory(session,tenant_id=user.tenant_id,device_id=device_id,
                serial=body.serial,udid=body.udid,actor_user_id=user.id)
            session.commit()
        except n.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        except IntegrityError:
            session.rollback();return error(409,"inventory already assigned to another device")
        return {"corrected":True,"hardware_attested":False,"moved_to_other_tenant":False}

    @app.delete("/api/mdm/devices/{device_id}/apple-inventory",dependencies=[Depends(require_csrf_header)])
    def release_inventory(device_id:int,body:FreshBody,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        denied=fresh_check(error,user,body.totp_code,body.confirm,"release-local-device-inventory")
        if denied is not None:return denied
        try:
            ade_web.release_inventory(session,tenant_id=user.tenant_id,device_id=device_id,actor_user_id=user.id)
            session.commit()
        except n.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        return {"local_inventory_released":True,"apple_business_released":False}
