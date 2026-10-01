# hunt-ps4104

Скан **Microsoft-Windows-PowerShell/Operational** (Event **4104**, Script Block Logging): ищет подозрительные script block’и, режет типичный шум, пишет отчёт на рабочий стол.

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/sweetvata/Y-PSOperational/main/hunt-ps4104.ps1 | iex"
```
ну как то так
```
love bypass by BypassMagister
```

## Куда пишет

```
%USERPROFILE%\Desktop\papa\PWSHOperational.txt
```

В консоли - краткий список alert’ов и полный путь к файлу.

Окно по времени: **последние 30 дней** в отчёте

## Метки 

| Метка | Смысл |
|--------|--------|
| **CRITICAL-LOADER** | AMSI/ETW/SBL + load/download в память - жёсткий evasion + payload |
| **FILELESS-STAGER** | bxor + gzip + `ScriptBlock::Create` - обёртка; payload может быть **следующим** 4104 в ту же минуту |
| **CHEAT-CLICKER** | Явный download + reflect (по сигнатурам вроде clicker) |
| **REVIEW-HIGH / REVIEW** | Подозрительные IOC, руками глянуть full block |
| **LOW** | Слабый match |


## Event Viewer руками

**Applications and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational**  
Фильтр: Event ID **4104** 

---
