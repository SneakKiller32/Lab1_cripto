from scapy.all import IP, ICMP, send

def enviar_icmp_string(destino, mensaje):
    # Patrón de 40 bytes del Data real del ping (sin cabeceras)
    patron_ping = bytes.fromhex(
        "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d"
        "1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b"
        "2c 2d 2e 2f 30 31 32 33 34 35 36 37"
    )
    assert len(patron_ping) == 40

    for caracter in mensaje:
        # reemplazar solo el primer byte
        payload = bytes([ord(caracter) & 0xFF]) + patron_ping[1:]
        assert len(payload) == 40

        paquete = IP(dst=destino) / ICMP(type=8) / payload
        send(paquete, verbose=False)
        print(f"Enviado carácter '{caracter}' a {destino}")

if __name__ == "__main__":
    destino = input("IP destino: ")
    mensaje = input("Mensaje a enviar (cifrado): ")
    enviar_icmp_string(destino, mensaje)
    print("Transmisión completada.")
# Este script envía un mensaje carácter por carácter en paquetes ICMP.
