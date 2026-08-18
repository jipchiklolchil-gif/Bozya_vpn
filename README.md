# Bozya_vpn

Скрипт собирает несколько подписок, фильтрует зарубежные серверы, делает TCP-проверки, выбирает до 50 лучших узлов и переименовывает их по странам.

## Что делает
- загружает подписки из `checker.py`
- исключает RU по названию и по IP-геолокации, если задан `IPINFO_TOKEN`
- делает 3 TCP-попытки на узел
- берёт только узлы с success rate >= 0.67
- ограничивает источники: `aska` до 5, `akonit` до 10
- обновляет результат каждые 5 часов через GitHub Actions

## Результат
- `output/top50.txt` — итоговая подписка
- `output/top50.b64.txt` — base64-вариант
- `output/report.json` — отчёт
- `output/summary.yaml` — сводка

## Как запустить в GitHub
1. Создай репозиторий `Bozya_vpn`
2. Загрузи эти файлы
3. При желании добавь secret `IPINFO_TOKEN`
4. Открой `Actions`
5. Запусти `Update VPN subscriptions`
6. Используй raw-ссылку на `output/top50.txt`

## Твоя ссылка
`https://raw.githubusercontent.com/jipchiklolchil-gif/Bozya_vpn/main/output/top50.txt`
