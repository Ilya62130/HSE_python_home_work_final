import json
import matplotlib
import pandas
import requests
import seaborn 
from configparser import ConfigParser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional



@dataclass(frozen=True)
class VirusTotalConfiguration:
    """Параметры доступа и эндпоинты VirusTotal."""

    api_key: str = field(default="", repr=False)
    url_ip: str = ""
    url_hash: str = ""
    url_domain: str = ""
    url_upload: str = ""


@dataclass(frozen=True)
class VulnersConfiguration:
    """Параметры доступа и эндпоинты Vulners."""

    api_key: str = field(default="", repr=False)
    url_search: str = ""
    url_cve_audit: str = ""
    url_cves_audit: str = ""
    url_software_audit: str = ""
    url_host_audit: str = ""

@dataclass(frozen=True)
class Configuration:
    """Загружает и хранит неизменяемую конфигурацию приложения."""

    virustotal: VirusTotalConfiguration = field(
        default_factory=VirusTotalConfiguration
    )
    vulners: VulnersConfiguration = field(
        default_factory=VulnersConfiguration
    )

    def __post_init__(self) -> None:
        """Загружает параметры из config.ini во время создания объекта."""
        config_path = Path(__file__).with_name("config.ini")
        config = ConfigParser()

        if not config.read(config_path, encoding="utf-8"):
            raise FileNotFoundError(
                f"Не найден файл конфигурации: {config_path}"
            )

        virustotal = VirusTotalConfiguration(
            api_key=config.get("virustotal", "API_KEY_VIRUS_TOTAL"),
            url_ip=config.get("virustotal", "URL_IP_VIRUS_TOTAL"),
            url_hash=config.get("virustotal", "URL_HASH_VIRUS_TOTAL"),
            url_domain=config.get("virustotal", "URL_DOMAIN_VIRUS_TOTAL"),
            url_upload=config.get("virustotal", "URL_UPLOAD_VIRUS_TOTAL"),
        )
        vulners = VulnersConfiguration(
            api_key=config.get("vulners", "API_KEY_VULNERS"),
            url_search=config.get("vulners", "URL_SEARCH_VULNERS"),
            url_cve_audit=config.get("vulners", "URL_CVE_AUDIT_VULNERS"),
            url_cves_audit=config.get("vulners", "URL_CVES_AUDIT_VULNERS"),
            url_software_audit=config.get(
                "vulners",
                "URL_SOFTWARE_AUDIT_VULNERS"
            ),
            url_host_audit=config.get(
                "vulners",
                "URL_HOST_AUDIT_VULNERS"
            ),
        )

        object.__setattr__(self, "virustotal", virustotal)
        object.__setattr__(self, "vulners", vulners)

    def __str__(self) -> str:
        """Возвращает параметры конфигурации в удобочитаемом виде."""
        vt = self.virustotal
        vulners = self.vulners
        vt_key = "<set>" if vt.api_key else "<not set>"
        vulners_key = "<set>" if vulners.api_key else "<not set>"

        return (
            "Configuration:\n"
            "  VirusTotal:\n"
            f"    API key: {vt_key}\n"
            f"    IP URL: {vt.url_ip}\n"
            f"    Hash URL: {vt.url_hash}\n"
            f"    Domain URL: {vt.url_domain}\n"
            f"    Upload URL: {vt.url_upload}\n"
            "  Vulners:\n"
            f"    API key: {vulners_key}\n"
            f"    Search URL: {vulners.url_search}\n"
            f"    CVE audit URL: {vulners.url_cve_audit}\n"
            f"    CVE list audit URL: {vulners.url_cves_audit}\n"
            f"    Software audit URL: {vulners.url_software_audit}\n"
            f"    Host audit URL: {vulners.url_host_audit}"
        )

if __name__ == "__main__":
    config = Configuration()
    print(config)