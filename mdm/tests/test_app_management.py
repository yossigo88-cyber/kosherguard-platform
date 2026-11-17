"""Application-management payload builders (structure-level; BUILT-UNVERIFIED
on device, per the module docstring)."""

import pytest

from mdm.app_management import (
    APP_MODES,
    LEGACY_PROFILE_IDENTIFIERS,
    PROFILE_IDENTIFIER,
    AppManagementError,
    application_access_payload,
    application_access_profile,
    install_application_command,
    app_settings_declaration,
    managed_application_list_command,
    remove_application_command,
    remove_profile_command,
    validate_bundle_id,
    validate_bundle_ids,
)


class TestBundleIDValidation:
    def test_accepts_reverse_dns(self):
        assert validate_bundle_id("com.example.app") == "com.example.app"
        assert validate_bundle_id("org.family-filter.safari-ext-2") == \
            "org.family-filter.safari-ext-2"

    @pytest.mark.parametrize("bad", [
        "", "noDots", ".leading.dot", "trailing.", "has space.com",
        "under_score.com", 123, None,
    ])
    def test_rejects_bad_forms(self, bad):
        with pytest.raises(AppManagementError):
            validate_bundle_id(bad)

    def test_list_dedupes_and_strips(self):
        assert validate_bundle_ids(
            [" com.a.b ", "com.a.b", "com.c.d"]) == ["com.a.b", "com.c.d"]

    def test_list_rejects_non_list(self):
        with pytest.raises(AppManagementError):
            validate_bundle_ids("com.a.b")


class TestApplicationAccessPayload:
    def test_blocklist_uses_documented_blocked_key(self):
        # blockedAppBundleIDs: documented current key (iOS 15+,
        # supervised, deprecated 27.0) in the full release YAML;
        # the legacy blacklistedAppBundleIDs (9.3, deprecated 15.0)
        # must NOT appear.
        p = application_access_payload("blocklist", ["com.bad.app"])
        assert p["PayloadType"] == "com.apple.applicationaccess"
        assert p["blockedAppBundleIDs"] == ["com.bad.app"]
        assert "allowListedAppBundleIDs" not in p
        assert "blacklistedAppBundleIDs" not in p

    def test_allowlist_uses_whitelist_key(self):
        p = application_access_payload("allowlist", ["com.good.app"])
        assert p["allowListedAppBundleIDs"] == ["com.good.app"]
        assert "blockedAppBundleIDs" not in p
        assert "blacklistedAppBundleIDs" not in p

    def test_rejects_unknown_mode(self):
        with pytest.raises(AppManagementError):
            application_access_payload("somelist", [])

    def test_modes_constant_matches_builders(self):
        assert set(APP_MODES) == {"blocklist", "allowlist"}

    def test_profile_wraps_payload(self):
        prof = application_access_profile("blocklist", ["com.bad.app"])
        assert prof["PayloadType"] == "Configuration"
        assert prof["PayloadScope"] == "System"
        assert len(prof["PayloadContent"]) == 1
        assert prof["PayloadContent"][0]["PayloadType"] == \
            "com.apple.applicationaccess"
        assert prof["PayloadUUID"] != \
            prof["PayloadContent"][0]["PayloadUUID"]

    def test_profile_identifier_is_stable_across_modes(self):
        # Review finding A1: one identifier means InstallProfile
        # replaces the on-device profile on a mode switch instead of
        # stacking a second profile whose restrictions can never be
        # lifted.
        block = application_access_profile("blocklist", ["com.bad.app"])
        allow = application_access_profile("allowlist", ["com.good.app"])
        assert block["PayloadIdentifier"] == PROFILE_IDENTIFIER
        assert allow["PayloadIdentifier"] == PROFILE_IDENTIFIER
        assert block["PayloadContent"][0]["PayloadIdentifier"] == \
            allow["PayloadContent"][0]["PayloadIdentifier"]
        assert PROFILE_IDENTIFIER not in LEGACY_PROFILE_IDENTIFIERS


class TestRemoveProfileCommand:
    def test_default_identifier_is_the_stable_profile(self):
        assert remove_profile_command() == {"Identifier": PROFILE_IDENTIFIER}

    def test_explicit_legacy_identifier(self):
        cmd = remove_profile_command(LEGACY_PROFILE_IDENTIFIERS[0])
        assert cmd == {"Identifier": LEGACY_PROFILE_IDENTIFIERS[0]}

    @pytest.mark.parametrize("bad", ["", "   ", None, 42])
    def test_rejects_empty_identifier(self, bad):
        with pytest.raises(AppManagementError):
            remove_profile_command(bad)


class TestAppCommands:
    def test_install_by_store_id(self):
        cmd = install_application_command(itunes_store_id=284815942)
        assert cmd["ITunesStoreID"] == 284815942
        assert cmd["Options"]["NotManaged"] is False

    def test_install_rejects_nonpositive_id(self):
        with pytest.raises(AppManagementError):
            install_application_command(itunes_store_id=0)
        with pytest.raises(AppManagementError):
            install_application_command(itunes_store_id="284815942")

    def test_install_bundle_id_alone_cannot_install(self):
        with pytest.raises(AppManagementError):
            install_application_command(bundle_id="com.example.app")

    def test_install_requires_something(self):
        with pytest.raises(AppManagementError):
            install_application_command()

    def test_remove_validates_identifier(self):
        assert remove_application_command("com.example.app") == \
            {"Identifier": "com.example.app"}
        with pytest.raises(AppManagementError):
            remove_application_command("not-a-bundle-id")

    def test_managed_list_is_empty_payload(self):
        assert managed_application_list_command() == {}


class TestAppSettingsDeclaration:
    """DDM com.apple.configuration.app.settings builder (schema-verified
    structure; BUILT-UNVERIFIED on device)."""

    def test_declaration_type_and_shape(self):
        d = app_settings_declaration("blocklist", ["com.bad.app"],
                                     server_token="t7")
        assert d["Type"] == "com.apple.configuration.app.settings"
        assert d["Identifier"] == "com.kosherguard.appsettings"
        assert d["ServerToken"] == "t7"
        assert d["Payload"] == {"Allowed": {
            "DeniedApps": [{"AppIdentifier": "com.bad.app"}]}}

    def test_allowlist_uses_allowed_apps(self):
        d = app_settings_declaration("allowlist",
                                     ["com.good.one", "com.good.two"])
        apps = d["Payload"]["Allowed"]["AllowedApps"]
        assert [a["AppIdentifier"] for a in apps] == \
            ["com.good.one", "com.good.two"]
        assert "DeniedApps" not in d["Payload"]["Allowed"]

    def test_default_server_token(self):
        d = app_settings_declaration("allowlist", [])
        assert d["ServerToken"] == "1"
        assert d["Payload"]["Allowed"]["AllowedApps"] == []

    def test_rejects_bad_mode_and_bad_ids(self):
        with pytest.raises(AppManagementError):
            app_settings_declaration("somelist", [])
        with pytest.raises(AppManagementError):
            app_settings_declaration("blocklist", ["no dots"])


class TestInstallConfiguration:
    """Managed-app configuration emission (spec Part 10 Applications).
    Contract verified against apple/device-management @ 9e7fdbe
    mdm/commands/application.install.yaml: Configuration, optional
    dictionary, iOS 7.0+/macOS 11.0+."""

    def test_configuration_emitted(self):
        cmd = install_application_command(
            itunes_store_id=284815942,
            configuration={"controlPlaneBaseURL": "https://cp.example.com",
                           "deviceID": 7})
        assert cmd["Configuration"] == {
            "controlPlaneBaseURL": "https://cp.example.com", "deviceID": 7}

    def test_no_configuration_no_key(self):
        cmd = install_application_command(itunes_store_id=284815942)
        assert "Configuration" not in cmd

    def test_configuration_must_be_dict(self):
        with pytest.raises(AppManagementError):
            install_application_command(itunes_store_id=1,
                                        configuration="not-a-dict")

    def test_configuration_must_be_json_serializable(self):
        with pytest.raises(AppManagementError):
            install_application_command(itunes_store_id=1,
                                        configuration={"k": object()})
