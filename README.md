# Auto VPN Russia — Security First

## iOS Double VPN Setup (Максимальная безопасность)

### Шаг 1: AmneziaVPN (защитный слой)
1. Скачай **AmneziaVPN** из App Store (бесплатно)
2. Импортируй файл `AMNEZIA_FREE.vpn` из этого репозитория
3. Подключись к любому серверу Amnezia Free

### Шаг 2: Karing (обход блокировок)
1. Скачай **Karing** из App Store
2. Импортируй ссылку: `https://raw.githubusercontent.com/ТВОЙ_NICKNAME/auto-vpn-russia/main/configs/output/SAFE_VLESS_RUS.txt`
3. Выбери сервер с пометкой `secure` → Подключись

**Результат:** Твой IP → Amnezia (скрыт) → VLESS (обход). Владелец VLESS-сервера не знает твой реальный IP.

## Файлы

| Файл | Назначение |
|------|-----------|
| `ALL_IN_ONE.txt` | Всё в одном (Karing) |
| `SAFE_VLESS_RUS.txt` | Только безопасные VLESS+Reality |
| `WARP_PLUS_WireGuard.txt` | WARP+ WireGuard конфиги |
| `AMNEZIA_FREE.vpn` | Amnezia Free `vpn://` ссылки |
| `TOR_BRIDGES.txt` | Tor мосты |
| `BLACK_*.txt` | По протоколам |

## Безопасность

| Уровень | Для чего | Как настроить |
|---------|----------|---------------|
| WARP+ | Банкинг, личные фото | Karing + `WARP_PLUS_WireGuard.txt` |
| Amnezia Free | Скрыть VPN от провайдера | AmneziaVPN app |
| VLESS+Reality | YouTube, TikTok, Telegram | Karing + `SAFE_VLESS_RUS.txt` |
| Double VPN | Максимум | AmneziaVPN + Karing |

**Важно:** Публичные VLESS-серверы — для видео и чатов. Для банкинга используй только WARP+.
