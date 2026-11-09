import json
import matplotlib
import pandas
import requests
import seaborn 
from configparser import ConfigParser
from pathlib import Path





def initialization():
    config = ConfigParser()
    config_path = Path(__file__).with_name("config.ini")
    if not config.read(config_path, encoding="utf-8"):
        raise FileNotFoundError(f"Не найден файл конфигурации: {config_path}")

    vt_api_key = config.get("virustotal", "API_KEY_VIRUS_TOTAL")
    vulners_api_key = config.get("vulners", "API_KEY_VULNERS")


if __name__ == "__main__":
    pass