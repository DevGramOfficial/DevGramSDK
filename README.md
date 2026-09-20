# DevGram SDK

Открытый исходный код системы плагинов DevGram: Python API, загрузчик
`.dgplugin`, нативный мост к Telegram Android и локальный Dev Server.

[Документация](https://docs.devgram.space/docs/introduction) ·
[DevGram Builder](https://github.com/DevGramOfficial/DevGramBuilder) ·
[DevGram](https://github.com/DevGramOfficial/DevGram) ·
[Канал новостей](https://t.me/DevGramNews)

## Что находится в репозитории

- [`python/devgram`](python/devgram) — публичный Python API, который импортирует
  плагин.
- [`python/devgram_plugins.py`](python/devgram_plugins.py) — настоящий загрузчик
  и реестр плагинов: проверка `.dgplugin`, распаковка, зависимости, загрузка,
  события и перезагрузка.
- [`android/org/telegram/messenger/DevGramPlugins.java`](android/org/telegram/messenger/DevGramPlugins.java)
  — нативный мост между Python и Telegram Android.
- [`android/org/telegram/messenger/DevGramDevServer.java`](android/org/telegram/messenger/DevGramDevServer.java)
  — локальный сервер разработки для загрузки и перезапуска плагинов через ADB.
- [`tools/dgplugin_tools.py`](tools/dgplugin_tools.py) — функции проверки,
  безопасной распаковки и анализа пакетов `.dgplugin`.

Это не переписанная документационная версия, а копия реально используемых
исходников DevGram. Текущий уровень API плагинов — **3**.

## С чего начать чтение

1. [`python/devgram/__init__.py`](python/devgram/__init__.py) — `BasePlugin`,
   события, отправка сообщений, настройки и хуки.
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — как проходят вызовы между
   пакетом, Python и Android.
3. [`python/devgram_plugins.py`](python/devgram_plugins.py) — жизненный цикл и
   проверка пакета.
4. [`docs/NATIVE_BRIDGE.md`](docs/NATIVE_BRIDGE.md) — устройство Java-моста и
   его зависимости.
5. [`docs/DGPLUGIN_FORMAT.md`](docs/DGPLUGIN_FORMAT.md) — содержимое пакета
   `.dgplugin`.

## Важно

Python SDK выполняется внутри DevGram на встроенном Python 3.11 через Chaquopy.
Модули используют `java.jclass`, поэтому их нельзя запустить как обычный пакет
CPython без Android-среды.

Java-мост зависит от классов Telegram Android, Chaquopy, Android SDK и
компонентов DevGram. Он опубликован отдельно для чтения, разработки API и
синхронизации изменений, но не является самостоятельным Android-приложением.

## Просмотр и распаковка `.dgplugin`

Пакет `.dgplugin` не зашифрован: это ZIP-архив с манифестом и открытыми
Python-исходниками. DevGram принимает только точку входа `.py` и отклоняет
архивы с байткодом `.pyc`/`.pyo`.

```bash
python3 tools/dgplugin.py info plugin.dgplugin --files
python3 tools/dgplugin.py unpack plugin.dgplugin
```

`unpack` безопасно извлекает исходники и ресурсы. Те же операции доступны как
функции `inspect_package` и `extract_package` из `tools.dgplugin_tools`.

## Синхронизация с DevGram

```bash
python3 tools/sync_from_devgram.py /path/to/DevGram
python3 tools/check_sources.py
```

Скрипт копирует только файлы SDK и записывает их SHA-256 в
`SOURCE_MANIFEST.json`. Сгенерированные `__pycache__` и файлы приложения в
репозиторий не попадают.

## Лицензия

Исходный код распространяется по лицензии GNU GPL v2. См. [LICENSE](LICENSE).
