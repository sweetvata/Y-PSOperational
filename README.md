# hunt-ps4104

Скан **Microsoft-Windows-PowerShell/Operational** (Event **4104**, Script Block Logging): ищет подозрительные script block’и, режет типичный шум, пишет отчёт на рабочий стол.

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/sweetvata/Y-PSOperational/main/hunt-ps4104.ps1 | iex"
```
ну как то так
```
love bypass by BypassMagister
```

## Зачем

4104 хранит текст выполненного PowerShell. Удобно для форензики и screenshare: stager’ы (base64/bxor/gzip), AMSI/ETW bypass, reflect load, download+execute и т.д.

**Ограничение:** если на машине уже гасили Script Block Logging (как в типичном CRITICAL-LOADER), **после этого** 4104 слепой — смотри события **до** первого LOG-KILL.

## Требования

- Windows с включённым **Script Block Logging** (иначе 4104 пустой или почти пустой).
- PowerShell 5.1+.
- Для чтения всего лога иногда нужны права админа.

## Запуск

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\hunt-ps4104.ps1
```

## Куда пишет

```
%USERPROFILE%\Desktop\papa\PWSHOperational.txt
```

В консоли — краткий список alert’ов и полный путь к файлу.

Окно по времени: **последние 30 дней** (см. строку `window last 30 days` в отчёте).

## Метки (verdict)

| Метка | Смысл |
|--------|--------|
| **CRITICAL-LOADER** | AMSI/ETW/SBL + load/download в память — жёсткий evasion + payload |
| **FILELESS-STAGER** | bxor + gzip + `ScriptBlock::Create` — обёртка; payload может быть **следующим** 4104 в ту же минуту |
| **CHEAT-CLICKER** | Явный download + reflect (по сигнатурам вроде clicker) |
| **REVIEW-HIGH / REVIEW** | Подозрительные IOC, руками глянуть full block |
| **LOW** | Слабый match |

**Не путать:** stager в логе = obfuscated **текст block’а**; «чистый» код часто в **отдельном** event сразу после `& $sb`.

## Что фильтруется (шум)

- Автоген **Defender** (`*-MpPreference`, `__cmdletization`, простыни `[Parameter(...)]`).
- Куски **Windows** troubleshooting.
- Обрезки одной строки (`GzipStream` / `MemoryStream` без контекста).
- Сам hunt и **Y-ClipBoard** (если гоняешь локально).

Короткий реальный вызов `Set-MpPreference -DisableRealtimeMonitoring $true` **не** режется.

## GitHub / приватность

- **Не комить** `papa\`, `PWSHOperational.txt`, decoded payload’ы — там логи с твоей машины.
- Пример `.gitignore`:

```gitignore
papa/
PWSHOperational.txt
*_decoded.txt
```

## Event Viewer руками

**Applications and Services Logs → Microsoft → Windows → PowerShell → Operational**  
Фильтр: Event ID **4104** (не путать с legacy **Windows PowerShell**).

---
