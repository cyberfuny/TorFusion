#!/bin/bash
# TorFusion Emergency Recovery Script
# Видаляє всі правила firewall TorFusion

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Потрібні права root"
    sudo "$0" "$@"
    exit $?
fi

echo "🔴 TorFusion Emergency Recovery"
echo "==============================="
echo ""
echo "Цей скрипт видалить усі правила firewall TorFusion."
echo ""

read -p "Виконати видалення? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Отмена"
    exit 0
fi

echo ""
echo "⏳ Видалення правил iptables..."

# Видаляємо TORFUSION ланцюги з OUTPUT
iptables -D OUTPUT -j TORFUSION 2>/dev/null || true
iptables -t nat -D OUTPUT -j TORFUSION_NAT 2>/dev/null || true
iptables -D FORWARD -j TORFUSION_FORWARD 2>/dev/null || true
iptables -t nat -D PREROUTING -j TORFUSION_NAT_FORWARD 2>/dev/null || true

# Очищуємо ланцюги
iptables -F TORFUSION 2>/dev/null || true
iptables -t nat -F TORFUSION_NAT 2>/dev/null || true
iptables -F TORFUSION_FORWARD 2>/dev/null || true
iptables -t nat -F TORFUSION_NAT_FORWARD 2>/dev/null || true

# Видаляємо ланцюги
iptables -X TORFUSION 2>/dev/null || true
iptables -t nat -X TORFUSION_NAT 2>/dev/null || true
iptables -X TORFUSION_FORWARD 2>/dev/null || true
iptables -t nat -X TORFUSION_NAT_FORWARD 2>/dev/null || true

# Видаляємо IPv6 fail-closed chains
ip6tables -D OUTPUT -j TORFUSION6 2>/dev/null || true
ip6tables -D FORWARD -j TORFUSION_FORWARD6 2>/dev/null || true
ip6tables -F TORFUSION6 2>/dev/null || true
ip6tables -F TORFUSION_FORWARD6 2>/dev/null || true
ip6tables -X TORFUSION6 2>/dev/null || true
ip6tables -X TORFUSION_FORWARD6 2>/dev/null || true

echo "✅ Правила firewall видалено"

# Перезапускаємо NetworkManager
echo "⏳ Перезапуск NetworkManager..."
systemctl restart NetworkManager || systemctl restart networking || true
echo "✅ NetworkManager перезапущено"

# Зупиняємо Tor
echo "⏳ Зупинка Tor..."
systemctl stop tor@default || systemctl stop tor || true
echo "✅ Tor зупинено"

echo ""
echo "✅ Відновлення завершено!"
echo ""
echo "Для перевірки мережі запустіть:"
echo "  ping -c 1 8.8.8.8"
echo ""
