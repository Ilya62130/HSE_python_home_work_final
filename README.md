# Automated Threat Monitoring and Response

Учебный проект на Python для автоматического мониторинга сетевых событий и выявления потенциальных угроз. Проект выполняет итоговое домашнее задание курса «Программирование на Python».

## Цель проекта

Программа должна:

- получать данные из API и/или сетевых журналов;
- выявлять подозрительные события и уязвимости;
- выводить уведомления о найденных угрозах;
- сохранять отчёт в формате JSON или CSV;
- строить график и сохранять его в PNG.

В проекте планируется использовать следующие источники данных:

1. VirusTotal API;
2. Vulners API;
3. тестовый набор Suricata-событий.

## Текущий статус

На данный момент реализована загрузка конфигурации приложения.

В [main.py](main.py) находятся три неизменяемых dataclass-класса:

- `VirusTotalConfiguration` — ключ API и адреса эндпоинтов VirusTotal;
- `VulnersConfiguration` — ключ API и адреса эндпоинтов Vulners;
- `Configuration` — объединённая конфигурация приложения.

Класс `Configuration` при создании автоматически читает файл `config.ini`, расположенный рядом с `main.py`.

Загрузка выполняется в методе `__post_init__`. После загрузки объект и вложенные объекты нельзя изменять благодаря `@dataclass(frozen=True)`.

Метод `__str__` выводит понятное описание конфигурации. Сами API-ключи при выводе не раскрываются: вместо них выводится состояние `<set>` или `<not set>`.

Пример запуска:

```powershell
python main.py
```

Пример вывода:

```text
Configuration:
  VirusTotal:
    API key: <set>
    IP URL: https://www.virustotal.com/api/v3/ip_addresses/
  Vulners:
    API key: <set>
    Search URL: https://vulners.com/api/v3/search/lucene
```

## Структура проекта

```text
HSE_python_home_work_final/
├── .gitignore
├── config.ini
├── data/
│   └── example_events.json
├── main.py
├── README.md
├── requirements.txt
└── TASK.md
```

Назначение файлов:

- `main.py` — основной файл приложения и классы конфигурации;
- `config.ini` — локальные API-ключи и URL эндпоинтов;
- `data/example_events.json` — тестовые события Suricata в формате JSON Lines;
- `TASK.md` — техническое задание;
- `requirements.txt` — необходимые сторонние библиотеки;
- `.gitignore` — исключения для секретов и локального окружения.

## Конфигурация

Файл `config.ini` должен содержать следующие секции:

```ini
[virustotal]
API_KEY_VIRUS_TOTAL =
URL_IP_VIRUS_TOTAL = https://www.virustotal.com/api/v3/ip_addresses/
URL_HASH_VIRUS_TOTAL = https://www.virustotal.com/api/v3/files/
URL_DOMAIN_VIRUS_TOTAL = https://www.virustotal.com/api/v3/domains/
URL_UPLOAD_VIRUS_TOTAL = https://www.virustotal.com/api/v3/files

[vulners]
API_KEY_VULNERS =
URL_SEARCH_VULNERS = https://vulners.com/api/v3/search/lucene
URL_CVE_AUDIT_VULNERS = https://vulners.com/api/v4/audit/cve
URL_CVES_AUDIT_VULNERS = https://vulners.com/api/v4/audit/cves
URL_SOFTWARE_AUDIT_VULNERS = https://vulners.com/api/v3/burp/softwareapi
URL_HOST_AUDIT_VULNERS = https://vulners.com/api/v3/audit/host

[suricata]
PATH_TO_EVE_LOG = data/example_events.json
```

Ключи вставляются без кавычек.

Секция `virustotal` содержит:

- ключ доступа VirusTotal;
- эндпоинт проверки IP-адреса;
- эндпоинт получения отчёта по хешу файла;
- эндпоинт проверки домена;
- эндпоинт загрузки файла.

Секция `vulners` содержит:

- ключ доступа Vulners;
- эндпоинт Lucene-поиска;
- эндпоинты аудита одной CVE и списка CVE;
- эндпоинт аудита ПО;
- эндпоинт аудита хоста.

API-ключи являются секретами. Не публикуйте заполненный `config.ini` в публичном репозитории и перевыпускайте ключи, если они уже попали в Git или в README.

## Виртуальное окружение

Создание окружения в Windows:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Если активация запрещена политикой PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Папка `.venv` должна быть исключена из Git.

## Установка зависимостей

Состав зависимостей находится в `requirements.txt`:

- `requests` — HTTP-запросы к API;
- `pandas` — обработка и анализ данных;
- `matplotlib` — построение графиков;
- `seaborn` — дополнительная визуализация.

Установка:

```powershell
python -m pip install -r requirements.txt
```

Проверка синтаксиса:

```powershell
python -m py_compile main.py
```

Запуск:

```powershell
python main.py
```

## Тестовые сетевые события

Файл [data/example_events.json](data/example_events.json) содержит примеры событий Suricata в формате JSON Lines. Одна JSON-запись размещается на одной строке.

В примерах используются типы событий:

- `alert` — сигнал о подозрительной активности;
- `dns` — DNS-запрос;
- `http` — HTTP-событие;
- `flow` — данные сетевого потока.

Alert-события могут описывать:

- подозрительную DNS-активность;
- необычную сетевую активность;
- возможное сканирование портов.

Эти события являются синтетическими и предназначены для тестирования программы, а не для анализа реальных вредоносных образцов.

## API-ресурсы

### VirusTotal

- [Overview of VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [Get an IP address report](https://docs.virustotal.com/reference/ip-info)
- [Get a file report](https://docs.virustotal.com/reference/file-info)
- [Upload a file](https://docs.virustotal.com/reference/files-scan)
- [Get a domain report](https://docs.virustotal.com/reference/domain-info)

Основные эндпоинты:

```text
GET  https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}
GET  https://www.virustotal.com/api/v3/files/{HASH}
POST https://www.virustotal.com/api/v3/files
GET  https://www.virustotal.com/api/v3/domains/{DOMAIN}
```

Для VirusTotal ключ передаётся в заголовке `x-apikey`.

### Vulners

- [Vulners API documentation](https://docs.vulners.com/docs/api/)
- [Vulners getting started](https://docs.vulners.com/docs/quickstart/)
- [Vulners search](https://docs.vulners.com/docs/guides/tutorials/vulners_search/)
- [Vulners audit API](https://docs.vulners.com/docs/api/audit/)

Основные эндпоинты:

```text
POST https://vulners.com/api/v3/search/lucene
POST https://vulners.com/api/v4/audit/cve
POST https://vulners.com/api/v4/audit/cves
POST https://vulners.com/api/v3/burp/softwareapi
POST https://vulners.com/api/v3/audit/host
```

Для Vulners ключ передаётся в заголовке `X-Api-Key`.

## План дальнейшей реализации

- [ ] Реализовать чтение тестовых Suricata-событий.
- [ ] Реализовать HTTP-запросы к VirusTotal.
- [ ] Реализовать HTTP-запросы к Vulners.
- [ ] Объединить данные из не менее чем двух источников.
- [ ] Добавить правила определения угроз.
- [ ] Реализовать реакцию на угрозу, например вывод сообщения в консоль.
- [ ] Сохранить итоговый отчёт в JSON или CSV.
- [ ] Построить график результатов в PNG.
- [ ] Проверить корректную работу при отсутствии ключей или недоступности API.
- [ ] Дополнить краткое описание каждого этапа анализа.

## Требования задания

- Python 3.8 или новее.
- Минимум два источника данных.
- Код `.py`.
- Обнаружение хотя бы одного типа угроз.
- Простое реагирование на обнаруженную угрозу.
- Отчёт в `.json` или `.csv`.
- График в `.png`.
- Открытый репозиторий GitHub для преподавателя.
- Отсутствие API-ключей и других секретов в репозитории.

Подробная формулировка задания находится в [TASK.md](TASK.md).
