<img width="1270" height="726" alt="photo_2026-09-20_00-40-38" src="https://github.com/user-attachments/assets/8f589a2c-4995-408a-b636-9b50dd74b59a" />

# TorFusion

https://github.com/user-attachments/assets/f2a5f865-1aa1-4d3c-872c-e203788a4a2b





TorFusion — Linux-застосунок на Go з TUI для керування Tor, прозорою
маршрутизацією TCP/DNS-трафіку, ротацією IP та діагностикою мережі.

## Зміст

- [Можливості](#можливості)
- [Як це працює](#як-це-працює)
- [Вимоги](#вимоги)
- [Встановлення та запуск](#встановлення-та-запуск)
- [TUI](#tui)
- [CLI](#cli)
- [Конфігурація](#конфігурація)
- [Transparent mode та firewall](#transparent-mode-та-firewall)
- [Proxy mode](#proxy-mode)
- [Ротація IP і країни](#ротація-ip-і-країни)
- [DNS-перевірка](#dns-перевірка)
- [Діагностика](#діагностика)
- [Відновлення мережі](#відновлення-мережі)
- [Тестування](#тестування)
- [Перевірка залежностей](#перевірка-залежностей)
- [Обмеження](#обмеження)
- [Безпечне використання](#безпечне-використання)

## Можливості

- TUI-інтерфейс українською мовою;
- transparent routing через керовані iptables-ланцюги;
- IPv6 fail-closed через окремі `ip6tables`-ланцюги;
- SOCKS proxy mode без зміни firewall;
- kill-switch для блокування прямого виходу, якщо Tor недоступний;
- автоматична перевірка готовності Tor перед зміною firewall;
- резервна копія поточних правил IPv4 та IPv6 firewall;
- безпечне видалення лише власних правил TorFusion;
- зміна Tor-ланцюжка через `SIGNAL NEWNYM`;
- cookie-автентифікація Tor ControlPort;
- вибір країни exit-ноди;
- автоматична ротація IP за інтервалом;
- отримання IP через Tor SOCKS5;
- DNS/SOCKS діагностика;
- статус служби Tor через systemd;
- перегляд журналу Tor через journalctl;
- JSON- та YAML-конфігурація;
- CLI для запуску без TUI;
- фоновий systemd-режим із запуском після перезавантаження;
- увімкнення та вимкнення фонового режиму безпосередньо з TUI;
- unit-тести, race detector, `go vet` та `govulncheck`.

## Як це працює

TorFusion керує локальним Tor:

```text
Застосунок → Tor SOCKS5 127.0.0.1:9050 → Tor network → exit node
```

У transparent mode для TCP/DNS додається перенаправлення:

```text
локальний TCP → iptables NAT → Tor TransPort 127.0.0.1:9040
локальний DNS → iptables NAT → Tor DNSPort 127.0.0.1:5353
```

Політика transparent mode — **Tor-only**: IPv4 TCP перенаправляється до Tor
TransPort, DNS UDP/53 — до Tor DNSPort, а інший зовнішній UDP і
непідтримувані протоколи блокуються. IPv6 блокується fail-closed через
`ip6tables`, оскільки поточний Tor transparent path не забезпечує безпечний
IPv6 `REDIRECT` до IPv4-портів Tor. Таким чином, IPv6 не виходить напряму.

TorFusion не очищає глобальні таблиці iptables. Він використовує власні
ланцюги:

```text
TORFUSION
TORFUSION_NAT
TORFUSION_FORWARD
TORFUSION_NAT_FORWARD
```

Для IPv6 используются отдельные filter-цепочки:

```text
TORFUSION6
TORFUSION_FORWARD6
```

## Вимоги

- Linux;
- Go 1.25 або новіший для збірки;
- встановлений Tor;
- `iptables` з підтримкою потрібних модулів;
- `ip6tables` для обов'язкового блокування IPv6-витоків;
- `systemctl`;
- `journalctl`;
- `curl`;
- root для редагування `/etc/tor/torrc` і firewall.

Встановлення системних пакетів у Debian/Kali:

```bash
sudo apt update
sudo apt install -y tor iptables iptables-nft curl netcat-openbsd
```

Перевірка версій:

```bash
go version
tor --version
iptables --version
curl --version
```

## Встановлення та запуск

Клонування або перехід до каталогу:

```bash
cd /home/kali/torfusion
```

Завантаження залежностей та збірка:

```bash
go mod tidy
go build -o torfusion .
```

Запуск TUI:

```bash
sudo ./torfusion
```

Неінтерактивний запуск:

```bash
sudo ./torfusion --action status
```

Якщо ви вже перебуваєте в root-shell через `sudo -i` або `sudo su`, повторний
`sudo` не потрібен:

```bash
sudo -i
cd /home/kali/torfusion
./torfusion
```

## TUI

Запустіть:

```bash
sudo ./torfusion
```

Доступні дії:

| Дія | Опис |
|---|---|
| Увімкнути прозору маршрутизацію Tor | Однією кнопкою встановлює/оновлює фоновий режим, запускає Tor і додає правила |
| Зупинити маршрутизацію / очистити правила | Видаляє тільки ланцюги TorFusion |
| Змінити Tor-ланцюжок | Надсилає `SIGNAL NEWNYM` |
| Оновити статус | Отримує IP через Tor SOCKS5 |
| Перевірити DNS-витік | Виконує запит через SOCKS5 |
| Показати статус служби Tor | Викликає `systemctl is-active tor@default` |
| Показати журнали Tor | Читає останні записи `journalctl` |
| Зберегти конфігурацію | Записує поточні налаштування |
| Увімкнути фоновий режим | Встановлює systemd-сервіс і запускає його після виходу з TUI |
| Вимкнути фоновий режим | Зупиняє сервіс, очищає правила та вимикає автозапуск |

Клавіші:

```text
↑/↓       переміщення
Enter     виконати дію / відкрити вибір інтервалу
i         відкрити меню інтервалу авто-ротації IP
r         змінити ланцюжок зараз
q         вийти
Ctrl+C    аварійно вийти
```

У нижньому рядку TUI показуються результат останньої дії та короткі підказки
щодо клавіш. Список дій адаптується до висоти термінала.

Перша кнопка автоматично встановлює або оновлює фоновий режим: копіює поточний
бінарник, зберігає конфігурацію, встановлює systemd-unit, запускає TorFusion і
застосовує firewall. Після цього TUI можна закрити — systemd продовжить роботу
TorFusion і відновить її після перезавантаження. Окремо вмикати фоновий режим
після першої кнопки не потрібно. Вимкнути його можна відповідним пунктом TUI.

У меню авто-ротації доступні значення: вимкнено, 30 секунд, 1 хвилина,
5 хвилин, 15 хвилин або власний режим. Власний режим вводиться прямо в цьому
ж меню: `5m` для фіксованого інтервалу, `30-120` для випадкового інтервалу,
`30s-2m` для діапазону з одиницями часу. Ротація завжди працює без обмеження
кількості змін, поки її не вимкнути. Підтримуються
`s`, `m`, `h`, `d`; максимальний інтервал — 86400 секунд.

TUI потребує справжнього термінала. При запуску через pipe, cron або середовище
без `/dev/tty` з’явиться помилка:

```text
could not open a new TTY
```

У такому випадку використовуйте CLI.

## CLI

Доступні дії:

```bash
./torfusion --action status
./torfusion --action ip
./torfusion --action dns
./torfusion --action logs
sudo ./torfusion --action daemon --config /etc/torfusion/config.json
sudo ./torfusion --action start
sudo ./torfusion --action stop
sudo ./torfusion --action rotate
```

Параметри:

```bash
--action    start, stop, rotate, daemon, ip, status, dns або logs
--country   код країни exit-ноди, наприклад de
--interval  сумісний фіксований інтервал у секундах; 0 вимикає ротацію
--config    шлях до JSON/YAML-конфігурації
--install   встановити та запустити фоновий systemd-режим
--uninstall зупинити фоновий режим, очистити правила та видалити його файли
```

Приклади:

```bash
sudo ./torfusion --action start --country de --interval 300
sudo ./torfusion --action rotate
./torfusion --action ip
./torfusion --action status
./torfusion --action dns
./torfusion --action logs
sudo ./torfusion --action stop
```

Для постоянной работы после выхода из TUI и перезагрузки установите systemd-
сервис. Он запускает transparent/proxy mode и выполняет автоматическую ротацию
самостоятельно, поэтому TUI можно закрыть:

```bash
sudo ./torfusion --install
```

Команда сама установит бинарник, сохранит текущий конфиг, включит автозапуск и
запустит фоновой режим. Если интервал равен `0`, маршрутизация будет работать
постоянно без автоматической смены IP.

Остановка `tor@default` не останавливает `torfusion.service`: в transparent
mode правила kill switch остаются активными и блокируют прямой выход до
восстановления Tor. Для полного отключения фонового режима используйте
`sudo ./torfusion --uninstall`, а не только остановку Tor.

Інтервал необов'язковий:

- фіксований інтервал або діапазон налаштовуються в тому самому
  пункті TUI;

`interval_min_seconds` і `interval_max_seconds` можна задати напряму у
JSON/YAML. Якщо вони не задані, старе поле `interval_seconds` автоматично
використовується як обидві межі. Формат `5m`, `30-120` або `30s-2m` вводиться
через TUI; CLI-прапорець `--interval` приймає фіксоване значення у секундах.

То же действие можно выполнить без выхода из TUI через пункт
**«Увімкнути фоновий режим»**.

После изменения параметров в TUI примените настройки той же командой:

```bash
sudo ./torfusion --install
```

Проверка фоновой ротации:

```bash
sudo systemctl status torfusion.service
sudo journalctl -u torfusion.service -f
```

Отмена фоновой задачи одной командой:

```bash
sudo ./torfusion --uninstall
```

Команда остановит сервис, очистит правила TorFusion, удалит автозапуск и
установленные системные файлы. Tor как системную службу она не удаляет.

Отключить фоновый режим можно также из TUI через пункт
**«Вимкнути фоновий режим»**.

## Конфігурація

Файл за замовчуванням:

```text
~/.config/torfusion/config.json
```

Інший файл можна вказати через:

```bash
export TORFUSION_CONFIG=/path/to/config.yaml
```

JSON-приклад:

```json
{
  "interval_seconds": 300,
  "interval_min_seconds": 300,
  "interval_max_seconds": 300,
  "country": "de",
  "kill_switch": true,
  "mode": "transparent",
  "log_lines": 100
}
```

Параметри:

| Поле | Значення |
|---|---|
| `interval_seconds` | 0–86400 секунд; 0 вимикає автоматичну ротацію |
| `interval_min_seconds` / `interval_max_seconds` | межі фіксованого або випадкового інтервалу; сумісні зі старим `interval_seconds` |
| `country` | код країни Tor або `auto` |
| `kill_switch` | `true` блокує прямий вихід при недоступному Tor |
| `mode` | `transparent` або `proxy` |
| `log_lines` | 1–10000 рядків журналу |

За замовчуванням:

```text
mode = transparent
kill_switch = true
country = auto
interval_seconds = 0
```

## Transparent mode та firewall

Перед застосуванням правил TorFusion виконує такі перевірки:

1. перевірка доступності Tor SOCKS5 `127.0.0.1:9050`;
2. перевірка готовності Tor через запит зовнішньої IP-адреси;
3. за потреби — оновлення та перевірка керованого блоку `torrc`;
4. резервне копіювання `iptables-save` і `ip6tables-save`;
5. створення або очищення керованих IPv4/IPv6-ланцюгів;
6. додавання правил NAT і filter.

Якщо Tor не готовий, firewall не змінюється.

Правила transparent mode:

- TCP перенаправляється на `TransPort 9040`;
- DNS UDP/53 перенаправляється на `DNSPort 5353`;
- інший UDP явно відхиляється, бо Tor не є прозорим UDP-проксі;
- непідтримуваний зовнішній трафік доходить до фінальної політики
  `REJECT` у kill-switch mode;
- Tor-користувач виключається з повторного перенаправлення;
- loopback і приватні мережі не спрямовуються через зовнішній Tor-маршрут;
- established/related-з’єднання не мають окремого обходу: після зупинки Tor
  уже відкриті з’єднання також блокуються kill switch;
- у kill-switch mode фінальне правило відхиляє невідповідний трафік;
- без kill-switch фінальне правило повертає обробку до наступних правил.
- IPv6-ланцюги `TORFUSION6` і `TORFUSION_FORWARD6` дозволяють лише
  loopback і локальні `fc00::/7` та `fe80::/10`;
  зовнішній IPv6 блокується.

Окремий TUI для ротації не потрібен: усі параметри змінюються в одному пункті
**«Авто-ротація IP»**. Після збереження конфігурації daemon використовує ті самі
налаштування. Для випадкового діапазону daemon обирає нову затримку перед кожною
зміною IP без обмеження кількості, доки ротацію не буде вимкнено.

Попередня реалізація з правилами, які відкидали `FIN/RST`, була небезпечною:
вона могла обривати існуючі з’єднання і заважати NetworkManager. Ці правила
видалені.

Перевірити правила від імені root:

```bash
sudo iptables -S OUTPUT
sudo iptables -t nat -S OUTPUT
sudo iptables -S TORFUSION
sudo iptables -t nat -S TORFUSION_NAT
sudo iptables -S TORFUSION_FORWARD
sudo iptables -t nat -S TORFUSION_NAT_FORWARD
sudo ip6tables -S TORFUSION6
sudo ip6tables -S TORFUSION_FORWARD6
sudo iptables -S OUTPUT
sudo iptables -S FORWARD
sudo iptables -t nat -S PREROUTING
sudo ip6tables -S OUTPUT
sudo ip6tables -S FORWARD
```

> Не запускайте transparent mode на віддаленому сервері без консольного доступу.
> Помилка в firewall може розірвати SSH-сеанс.

У kill-switch режимі IPv6 навмисно не проксіюється через Tor, а блокується
fail-closed. Це захищає від IPv6 leak, але означає, що IPv6-з'єднання не
працюватимуть через transparent mode.

## Proxy mode

У режимі:

```json
{
  "mode": "proxy",
  "kill_switch": false
}
```

TorFusion запускає та налаштовує Tor, але не змінює iptables. Програми потрібно
налаштувати на:

```text
SOCKS5 host: 127.0.0.1
SOCKS5 port: 9050
```

Для DNS через SOCKS5 використовуйте SOCKS5 hostname resolution, наприклад:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

## Ротація IP і країни

Одноразова зміна ланцюжка:

```bash
sudo ./torfusion --action rotate
```

Ручний запуск daemon для діагностики:

```bash
sudo ./torfusion --action daemon --config /etc/torfusion/config.json
```

Для звичайного використання краще обирати пункт TUI або використовувати
`--install`: systemd автоматично перезапустить daemon після збою та запустить
його після перезавантаження.

Країна додається до керованої частини `torrc`:

```text
ExitNodes {DE}
StrictNodes 1
```

Для автоматичного вибору exit-ноди:

```json
{
  "country": "auto"
}
```

Для зміни ланцюжка використовується Tor ControlPort `9051` і cookie-файл:

```text
/run/tor/control.authcookie
/var/lib/tor/control_auth_cookie
```

## DNS-перевірка

Діагностична команда:

```bash
./torfusion --action dns
```

Вона виконує запит через:

```bash
curl --socks5-hostname 127.0.0.1:9050 \
  --max-time 15 \
  https://1.1.1.1/cdn-cgi/trace
```

Це перевіряє роботу запиту через SOCKS5 і показує дані Cloudflare. Це не є
повним зовнішнім аудитом DNS-політики та не гарантує відсутність усіх типів
витоків у сторонніх програмах.

## Діагностика

Перевірити службу:

```bash
sudo systemctl is-active tor@default
sudo systemctl status tor@default
```

Перевірити SOCKS5:

```bash
nc -zv 127.0.0.1 9050
```

Перевірити IP через Tor:

```bash
curl --socks5-hostname 127.0.0.1:9050 \
  https://check.torproject.org/api/ip
```

Переглянути журнали:

```bash
sudo journalctl -u tor@default -n 100 --no-pager
./torfusion --action logs
```

Типова помилка:

```text
socks connect tcp 127.0.0.1:9050
```

означає, що порт SOCKS5 недоступний або Tor ще не завершив запуск. Перевірте:

```bash
sudo systemctl reset-failed tor@default
sudo systemctl start tor@default
sudo systemctl is-active tor@default
nc -zv 127.0.0.1 9050
```

## Відновлення мережі

TorFusion створює резервну копію через `iptables-save` та `ip6tables-save` перед застосуванням
transparent rules. Також у проєкті є аварійний скрипт:

```bash
sudo ./restore.sh
```

Скрипт:

1. видаляє jump до `TORFUSION`;
2. видаляє jump до `TORFUSION_NAT`;
3. видаляє jumps до `TORFUSION_FORWARD` і `TORFUSION_NAT_FORWARD`;
4. очищує та видаляє IPv4-ланцюги TorFusion;
5. видаляє IPv6 hooks, очищує та видаляє `TORFUSION6` і
   `TORFUSION_FORWARD6`;
6. перезапускає NetworkManager або networking;
7. зупиняє Tor.

Перевірка після відновлення:

```bash
ping -c 1 8.8.8.8
curl https://example.com
```

Ручне аварійне очищення:

```bash
sudo iptables -D OUTPUT -j TORFUSION 2>/dev/null || true
sudo iptables -t nat -D OUTPUT -j TORFUSION_NAT 2>/dev/null || true
sudo iptables -D FORWARD -j TORFUSION_FORWARD 2>/dev/null || true
sudo iptables -t nat -D PREROUTING -j TORFUSION_NAT_FORWARD 2>/dev/null || true
sudo iptables -F TORFUSION 2>/dev/null || true
sudo iptables -t nat -F TORFUSION_NAT 2>/dev/null || true
sudo iptables -F TORFUSION_FORWARD 2>/dev/null || true
sudo iptables -t nat -F TORFUSION_NAT_FORWARD 2>/dev/null || true
sudo iptables -X TORFUSION 2>/dev/null || true
sudo iptables -t nat -X TORFUSION_NAT 2>/dev/null || true
sudo iptables -X TORFUSION_FORWARD 2>/dev/null || true
sudo iptables -t nat -X TORFUSION_NAT_FORWARD 2>/dev/null || true
sudo ip6tables -D OUTPUT -j TORFUSION6 2>/dev/null || true
sudo ip6tables -D FORWARD -j TORFUSION_FORWARD6 2>/dev/null || true
sudo ip6tables -F TORFUSION6 2>/dev/null || true
sudo ip6tables -F TORFUSION_FORWARD6 2>/dev/null || true
sudo ip6tables -X TORFUSION6 2>/dev/null || true
sudo ip6tables -X TORFUSION_FORWARD6 2>/dev/null || true
sudo systemctl restart NetworkManager
```

> Не використовуйте `iptables -F` або `iptables -X` без розуміння наслідків:
> вони можуть знищити правила інших застосунків.

## Тестування

Запуск unit-тестів:

```bash
go test ./...
```

Перевірка на data races:

```bash
go test -race ./...
```

Перевірка покриття:

```bash
go test -cover ./...
```

Статичний аналіз:

```bash
go vet ./...
```

Збірка:

```bash
go build -o torfusion .
```

Поточні тести перевіряють:

- серіалізацію JSON-конфігурації;
- значення за замовчуванням;
- створення керованих firewall-ланцюгів;
- kill-switch;
- режим без kill-switch;
- локальні та приватні підмережі;
- видалення власних правил;
- відсутність небезпечних `FIN/RST DROP`;
- перевірку системних команд;
- обробку timeout-контексту.

Тести firewall використовують fake runner і не змінюють реальні правила
системи.

## Перевірка залежностей

Синхронізація модулів:

```bash
go mod tidy
```

Перевірка цілісності:

```bash
go mod verify
```

Встановлення офіційного сканера Go:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

Запуск:

```bash
$(go env GOPATH)/bin/govulncheck ./...
```

Якщо каталог Go binary не входить у `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
govulncheck ./...
```

Після оновлення залежностей поточна перевірка показала:

```text
go mod verify: all modules verified
govulncheck: No vulnerabilities found
```

## Обмеження

- підтримується Linux та iptables-сумісний backend; нативний API nftables
  напряму не використовується;
- transparent UDP не підтримується Tor і не маскується під TCP;
- IPv6 у transparent mode блокується, а не проксіюється через Tor;
- DNS-перевірка є діагностичною, а не повним аудитом системи;
- TUI не працює без справжнього TTY;
- правила TorFusion охоплюють локальные `OUTPUT` и транзитные `FORWARD`;
- потрібні права root для системної конфігурації та firewall.

## Безпечне використання

TorFusion призначений для приватності, власних систем і дозволеного
тестування. Tor не робить користувача невразливим: exit-ноди можуть бути
скомпрометовані, заблоковані або повільними.

Не використовуйте застосунок для обходу політик мереж, несанкціонованого
доступу або приховування незаконної активності. Перед зміною firewall майте
доступ до локальної консолі або перевірений аварійний канал.

## Ліцензія

Перевірте ліцензійні умови залежностей та компонентів, які використовуються
під час розповсюдження готового бінарника.
