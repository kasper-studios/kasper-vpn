# KasperVPN Client

Нативный клиент и сплит-туннель для сервиса KasperVPN.

- **Desktop GUI**: Оконное приложение на базе Tauri 2.0 (системный трей, автоматическая настройка системного прокси)
- **CLI Daemon**: Легковесный сплит-туннель клиент на Rust
- **Туннель**: sing-box VLESS Reality

## Сборка

```bash
# Сборка CLI клиента
cd app && cargo build --release

# Сборка Desktop GUI
cd app/src-tauri && cargo build --release
```
