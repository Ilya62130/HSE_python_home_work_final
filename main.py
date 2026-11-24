import pandas as pd
from configparser import ConfigParser
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


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
class SuricataConfiguration:
    """Хранит путь до журнала Suricata."""

    path_to_eve_log: str = ""
    

class LogColumnName(str, Enum):
    """Перечисляет имена используемых столбцов журнала Suricata."""

    TIMESTAMP = "timestamp"
    FLOW_ID = "flow_id"
    EVENT_TYPE = "event_type"
    SOURCE_IP = "src_ip"
    SOURCE_PORT = "src_port"
    DESTINATION_IP = "dest_ip"
    DESTINATION_PORT = "dest_port"
    PROTOCOL = "proto"
    HTTP = "http"
    ALERT = "alert"
    DNS = "dns"
    FLOW = "flow"


@dataclass(frozen=True)
class Configuration:
    """Загружает и хранит неизменяемую конфигурацию приложения."""

    virustotal: VirusTotalConfiguration = field(
        default_factory=VirusTotalConfiguration
    )
    vulners: VulnersConfiguration = field(
        default_factory=VulnersConfiguration
    )
    suricata: SuricataConfiguration = field(
        default_factory=SuricataConfiguration
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
        suricata = SuricataConfiguration(
            path_to_eve_log=config.get(
                "suricata",
                "PATH_TO_EVE_LOG"
            )
        )

        object.__setattr__(self, "virustotal", virustotal)
        object.__setattr__(self, "vulners", vulners)
        object.__setattr__(self, "suricata", suricata)

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
            f"    Host audit URL: {vulners.url_host_audit}\n"
            "  Suricata:\n"
            f"    EVE log: {self.suricata.path_to_eve_log}"
        )

class SuricataLogReader:
    """Читает журнал и предоставляет исходные события."""

    def __init__(self, path_suricata_log: str) -> None:
        """Формирует путь до журнала и загружает его при создании объекта."""
        log_path = Path(path_suricata_log)
        project_path = Path(__file__).resolve().parent

        if not log_path.is_absolute():
            log_path = project_path / log_path

        if not log_path.is_file():
            raise FileNotFoundError(
                f"Не найден журнал Suricata: {log_path}"
            )

        self._path_suricata_log = log_path
        self._dataframe_log = self._read_events()

    def _read_events(self) -> pd.DataFrame:
        """Читает JSON Lines-журнал и возвращает таблицу pandas."""
        return pd.read_json(
            self._path_suricata_log,
            lines=True,
            encoding="utf-8"
        )

    @property
    def path_suricata_log(self) -> Path:
        """Возвращает абсолютный путь до журнала Suricata."""
        return self._path_suricata_log

    @property
    def dataframe_log_copy(self) -> pd.DataFrame:
        """Возвращает копию журнала Suricata в виде таблицы pandas."""
        return self._dataframe_log.copy()
    
if __name__ == "__main__":
    config = Configuration()
    print(config)