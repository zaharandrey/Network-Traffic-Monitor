from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import asyncio

# Конфігурація
INTERFACE = "eth0"  # Інтерфейс для моніторингу
THRESHOLD_PACKETS = 100  # Порогове значення пакетів від одного IP за хвилину
THRESHOLD_PORT_SCAN = 10  # Порогове значення відкритих портів для сканування
LOG_FILE = "alerts.log"

# Дані для аналізу
traffic_data = defaultdict(int)  # Кількість пакетів від кожного IP
port_scan_data = defaultdict(set)  # Порти, до яких зверталися з кожного IP

# Функція для запису логів
def log_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")
    print(message)

# Аналіз кожного пакета
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src

        # Підрахунок кількості пакетів від кожного джерела
        traffic_data[src_ip] += 1

        # Аналіз TCP-пакетів для виявлення сканування портів
        if TCP in packet:
            dst_port = packet[TCP].dport
            port_scan_data[src_ip].add(dst_port)

# Функція для перевірки на загрози
async def detect_anomalies():
    while True:
        await asyncio.sleep(60)  # Аналіз кожну хвилину

        # Перевірка на аномально велику кількість пакетів
        for ip, count in traffic_data.items():
            if count > THRESHOLD_PACKETS:
                log_alert(f"Підозріла активність: {ip} надіслав {count} пакетів за хвилину!")

        # Перевірка на сканування портів
        for ip, ports in port_scan_data.items():
            if len(ports) > THRESHOLD_PORT_SCAN:
                log_alert(f"Підозра на сканування портів: {ip} звертався до {len(ports)} портів!")

        # Очистка даних після перевірки
        traffic_data.clear()
        port_scan_data.clear()

# Основна функція запуску програми
async def main():
    print("Запуск перехоплення трафіку...")
    log_alert("Система моніторингу запущена")

    # Запуск аналізу аномалій в асинхронному режимі
    asyncio.create_task(detect_anomalies())

    # Перехоплення трафіку
    sniff(iface=INTERFACE, prn=analyze_packet, store=False)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Зупинка програми.")

