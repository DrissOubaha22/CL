"""Product to CPE resolution and the import contract - spec §3.1, §3.2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.core.enums import Criticality, ExposureClass
from aegis.inventory.loader import InventoryLoadError, load_inventory_file
from aegis.inventory.normalise import resolve_product, slugify_component
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource


class TestSlugify:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("Apache HTTP Server", "apache_http_server"),
            ("FortiOS", "fortios"),
            ("Acme Inc.", "acme"),
            ("  Citrix  NetScaler  ", "citrix_netscaler"),
            ("node.js", "node_js"),
        ],
    )
    def test_slugify(self, value: str, expected: str) -> None:
        assert slugify_component(value) == expected

    def test_a_name_made_only_of_noise_keeps_its_tokens(self) -> None:
        """Dropping every token would lose the product entirely."""
        assert slugify_component("Software") == "software"


class TestResolveProduct:
    def test_curated_alias_is_authoritative(self) -> None:
        resolved = resolve_product(product="FortiOS", version="7.4.2")
        assert resolved.is_authoritative
        assert [c.to_string() for c in resolved.cpes] == [
            "cpe:2.3:o:fortinet:fortios:7.4.2:*:*:*:*:*:*:*"
        ]

    def test_one_product_can_resolve_to_several_spellings(self) -> None:
        """Spec §3.2: "one or more CPE strings"."""
        resolved = resolve_product(product="Apache HTTP Server", version="2.4.58")
        products = {c.product for c in resolved.cpes}
        assert products == {"http_server", "httpd"}

    def test_a_banner_may_carry_the_vendor_prefix(self) -> None:
        resolved = resolve_product(product="Microsoft Exchange Server", version="15.2")
        assert resolved.is_authoritative
        assert resolved.cpes[0].vendor == "microsoft"
        assert resolved.cpes[0].product == "exchange_server"

    def test_vendor_and_product_may_arrive_separately(self) -> None:
        resolved = resolve_product(product="Tomcat", vendor="Apache", version="9.0.50")
        assert resolved.cpes[0].to_string().startswith("cpe:2.3:a:apache:tomcat:")

    def test_supplied_cpes_are_trusted_verbatim(self) -> None:
        """Scanners often already know the CPE."""
        resolved = resolve_product(
            product="whatever",
            supplied_cpes=["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"],
        )
        assert resolved.is_authoritative
        assert resolved.cpes[0].product == "nginx"

    def test_a_malformed_supplied_cpe_is_dropped_not_fatal(self) -> None:
        resolved = resolve_product(product="FortiOS", supplied_cpes=["not-a-cpe"])
        assert all(c.product == "fortios" for c in resolved.cpes)

    def test_unknown_product_falls_back_and_is_marked_guessed(self) -> None:
        resolved = resolve_product(
            product="Totally Unknown Widget", vendor="Acme Inc", version="1.0"
        )
        assert not resolved.is_authoritative
        assert resolved.cpes[0].to_string() == (
            "cpe:2.3:a:acme:totally_unknown_widget:1.0:*:*:*:*:*:*:*"
        )

    def test_missing_version_becomes_a_wildcard(self) -> None:
        resolved = resolve_product(product="FortiOS")
        assert resolved.cpes[0].version == "*"


class TestInventoryItem:
    def test_hostname_is_normalised(self) -> None:
        item = InventoryItem(hostname="  VPN.Acme.Test. ", product="FortiOS")
        assert item.hostname == "vpn.acme.test"

    @pytest.mark.parametrize("placeholder", ["", "-", "n/a", "unknown", "none", "*", "  "])
    def test_version_placeholders_become_null(self, placeholder: str) -> None:
        """Storing "unknown" as a version would make it look orderable."""
        assert InventoryItem(hostname="h", product="p", version=placeholder).version is None

    @pytest.mark.parametrize(
        ("evidence", "expected"),
        [
            (DiscoveryEvidence.ANSWERED_PUBLICLY, ExposureClass.INTERNET),
            (DiscoveryEvidence.SEEN_INTERNALLY, ExposureClass.INTERNAL),
            (DiscoveryEvidence.INSTALLED_ON_ENDPOINT, ExposureClass.CLIENT_SIDE),
            (DiscoveryEvidence.UNKNOWN, ExposureClass.UNKNOWN),
        ],
    )
    def test_exposure_derives_from_evidence(
        self, evidence: DiscoveryEvidence, expected: ExposureClass
    ) -> None:
        """Spec §3.2: exposure comes from evidence, not a self-declared field."""
        item = InventoryItem(hostname="h", product="p", evidence=evidence)
        assert item.exposure_class is expected

    def test_exposure_cannot_be_declared_directly(self) -> None:
        with pytest.raises(ValidationError):
            InventoryItem(
                hostname="h",
                product="p",
                exposure_class=ExposureClass.INTERNET,  # type: ignore[call-arg]
            )

    def test_unknown_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            InventoryItem(hostname="h", product="p", severity="critical")  # type: ignore[call-arg]

    def test_port_must_be_a_real_port(self) -> None:
        with pytest.raises(ValidationError):
            InventoryItem(hostname="h", product="p", port=70000)


class TestLoader:
    def test_loads_a_json_array(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "hostname": "vpn.acme.test",
                        "product": "FortiOS",
                        "version": "7.4.1",
                        "evidence": "answered_publicly",
                        "criticality": "high",
                    }
                ]
            )
        )
        batch = load_inventory_file(path)
        assert len(batch.items) == 1
        assert batch.items[0].criticality is Criticality.HIGH
        assert batch.items[0].exposure_class is ExposureClass.INTERNET

    def test_loads_a_csv_with_typed_columns(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.csv"
        path.write_text(
            "hostname,product,version,evidence,from_distro_package,port,cpes\n"
            "db1,openssl,3.0.2,seen_internally,true,5432,"
            "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*\n"
        )
        item = load_inventory_file(path).items[0]
        assert item.port == 5432
        assert item.from_distro_package is True
        assert item.cpes == ["cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"]

    def test_blank_csv_cells_fall_back_to_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.csv"
        path.write_text("hostname,product,version,port\nh1,nginx,1.24.0,\n")
        item = load_inventory_file(path).items[0]
        assert item.port is None

    def test_source_override_applies_to_every_item(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.csv"
        path.write_text("hostname,product\nh1,nginx\nh2,tomcat\n")
        batch = load_inventory_file(path, source=InventorySource.SCANNER)
        assert {item.source for item in batch.items} == {InventorySource.SCANNER}

    def test_a_bad_row_names_its_line(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.csv"
        path.write_text("hostname,product\nh1,nginx\n,tomcat\n")
        with pytest.raises(InventoryLoadError, match=r":3:"):
            load_inventory_file(path)

    def test_unknown_extension_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.xlsx"
        path.write_text("nope")
        with pytest.raises(InventoryLoadError, match="unsupported"):
            load_inventory_file(path)

    def test_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InventoryLoadError, match="no such"):
            load_inventory_file(tmp_path / "absent.json")
