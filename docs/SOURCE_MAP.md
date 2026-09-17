# Карта исходников

| Файл в этом репозитории | Файл в DevGram |
| --- | --- |
| `python/devgram/**` | `TMessagesProj/src/main/python/devgram/**` |
| `python/devgram_plugins.py` | `TMessagesProj/src/main/python/devgram_plugins.py` |
| `android/org/telegram/messenger/DevGramPlugins.java` | `TMessagesProj/src/main/java/org/telegram/messenger/DevGramPlugins.java` |
| `android/org/telegram/messenger/DevGramDevServer.java` | `TMessagesProj/src/main/java/org/telegram/messenger/DevGramDevServer.java` |

`SOURCE_MANIFEST.json` создаётся скриптом синхронизации и содержит commit
исходного репозитория, список локально изменённых исходников на момент
синхронизации и SHA-256 каждого опубликованного файла. Это позволяет проверить,
какой именно код был скопирован.
