'use strict';
// Same-origin only. Secrets are never placed in URLs/localStorage or echoed.
const status = document.getElementById('status');
let deviceID = null;
async function call(path, body) {
  const response = await fetch(path, {method:body ? 'POST' : 'GET', credentials:'same-origin', cache:'no-store', headers:{'Content-Type':'application/json','X-KosherGuard-Request':'1'},body:body ? JSON.stringify(body) : undefined});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || result.detail || 'Request refused');
  return result;
}
document.getElementById('login').addEventListener('submit', async event => {
  event.preventDefault();
  status.textContent = 'Checking guardian sign-in...';
  try {
    const signed = await call('/api/auth/login', {email:document.getElementById('email').value,tenant_name:document.getElementById('tenant').value,password:document.getElementById('password').value,totp_code:document.getElementById('totp').value});
    document.getElementById('password').value = '';
    document.getElementById('totp').value = '';
    if (signed.mfa_required) throw new Error('Set up guardian MFA in the existing account settings before enrollment. No password-only enrollment is allowed.');
    const info = await call('/api/mdm/ade/ceremony');
    deviceID = info.device_id;
    document.getElementById('inventory').textContent = 'Serial: ' + info.serial + '\nUDID: ' + info.udid + '\nMatch these to the physical spare device before continuing.';
    document.getElementById('approval').hidden = false;
    status.textContent = 'Guardian signed in. Review the device before approving.';
  } catch (error) { status.textContent = error.message; }
});
document.getElementById('authorize').addEventListener('click', async () => {
  const button = document.getElementById('authorize');
  button.disabled = true;
  try {
    const result = await call('/api/mdm/ade/authorize', {device_id:deviceID,restart:document.getElementById('restart').checked});
    status.textContent = 'Downloading the one-use signed enrollment profile. Follow the system instructions; installation is not yet confirmed.';
    // Server-returned same-origin relative final URL, never a blob/third-party host.
    if (!/^\/api\/mdm\/ade\/profile\/[A-Za-z0-9_-]+$/.test(result.profile_path)) throw new Error('Invalid profile destination');
    window.location.assign(result.profile_path);
  } catch (error) { status.textContent = error.message; button.disabled = false; }
});
