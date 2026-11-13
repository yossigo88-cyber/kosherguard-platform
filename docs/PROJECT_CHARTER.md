# KosherGuard Platform - Project Charter

## Goal

Build a complete iPhone filtering and management platform. The platform gives parents and administrators central, remote control over managed iPhones: what websites and content categories each device can reach, which apps are restricted, and how policies are delivered, updated, and restored.

## Components

1. **Central server** - the backend service that stores device and policy state and serves all platform APIs.
2. **Administrator dashboard** - the web interface administrators use to enroll devices, set filtering rules and app restrictions, and monitor device state.
3. **Website and category filtering** - web filtering by URL and content category for managed devices.
4. **Supported app restrictions** - block or allow apps on managed devices using Apple-supported restriction mechanisms.
5. **Device enrollment** - a supported, documented flow that brings an iPhone under management and establishes its trusted identity with the server.
6. **Push-triggered policy updates** - the server can push policy changes to devices so updates take effect without manual action on the device.
7. **Recovery after device resets** - a documented path to bring a device back under management and restore its policy after an erase or reset.

## Working principles

- GitHub is the permanent source of truth. Project files live in this repository, not in external file shares or temporary links.
- No secrets in the repository: no passwords, API keys, certificates, private keys, or tokens.
- Staged development: each stage is reviewed and approved before the next begins. No application code is written until this charter stage is approved.
- Brand-new codebase: nothing is used, imported, copied, or modified from any earlier project.
- Apple capability claims are checked against current Apple documentation when the relevant stage is built.
