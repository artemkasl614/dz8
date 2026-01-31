
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse

def process_packet(packet):
    """
    Обработка каждого перехваченного пакета.
    Фильтруем HTTP запросы и ответы для анализа трафика Gruyere.
    """
    if packet.haslayer(HTTPRequest):
        # Извлекаем хост и путь
        host = packet[HTTPRequest].Host.decode(errors='ignore')
        path = packet[HTTPRequest].Path.decode(errors='ignore')
        method = packet[HTTPRequest].Method.decode(errors='ignore')
        
        print(f"\n[>] HTTP Request: {method} {host}{path}")
        
        # Если есть полезная нагрузка (например, POST данные)
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode(errors='ignore')
            print(f"[*] Raw Payload: {load}")
            if "alert" in load or "<script>" in load:
                print("[!!!] ВНИМАНИЕ: Обнаружена попытка XSS инъекции в исходящем трафике!")

    if packet.haslayer(HTTPResponse):
        print(f"[<] HTTP Response received from {packet[IP].src}")
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode(errors='ignore')
            # Поиск следов XSS в ответе сервера (Reflection)
            if "alert(" in load:
                print("[!!!] ОБНАРУЖЕНО: Вредоносный код вернулся в теле ответа сервера (Reflected XSS)")

def start_sniffing():
    print("[*] Запуск перехвата трафика на порту 80...")
    print("[*] Ожидание пакетов от google-gruyere.appspot.com...")
    # Фильтруем только TCP трафик на 80 порту (HTTP)
    sniff(filter="tcp port 80", prn=process_packet, store=False)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[*] Анализ остановлен пользователем.")
    except PermissionError:
        print("[!] Ошибка: Для работы с сырыми сокетами Scapy требуются права администратора (sudo).")
