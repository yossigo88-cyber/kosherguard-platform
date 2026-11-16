"""Application-management payload builders (structure-level; BUILT-UNVERIFIED
on device, per the module docstring)."""

import pytest

from mdm.app_management import (
    APP_MODES,
    AppManagementError,
    application_access_payload,
    application_access_profile,
    install_application_command,
    app_settings_declaration,
    managed_application_list_command,
    remove_application_command,
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
    def test_blocklist_uses_blacklist_key(self):
        p = application_access_payload("blocklist", ["com.bad.app"])
        assert p["PayloadType"] == "com.apple.applicationaccess"
        assert p["blacklistedAppBundleIDs"] == ["com.bad.app"]
        assert "whiteListedAppBundleIDs" not in p

    def test_allowlist_uses_whitelist_key(self):
        p = application_access_payload("allowlist", ["com.good.app"])
        assert p["whiteListedAppBundleIDs"] == ["com.good.app"]
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
        assert d["Identifier"] == "com.kosherguard.appsettings.blocklist"
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
