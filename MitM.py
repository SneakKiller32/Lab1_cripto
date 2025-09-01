from scapy.all import sniff, ICMP
from colorama import Fore, Style

mensaje_cifrado = []

# Descifrado César
def descifrar_cesar(texto, clave):
    resultado = ""
    for c in texto:
        if 'A' <= c <= 'Z':
            resultado += chr((ord(c) - ord('A') - clave) % 26 + ord('A'))
        elif 'a' <= c <= 'z':
            resultado += chr((ord(c) - ord('a') - clave) % 26 + ord('a'))
        else:
            resultado += c
    return resultado

# Función para score basado en frecuencia de letras españolas
letras_comunes = "eaosrndilc"
def score_frecuencia(texto):
    texto = texto.lower()
    return sum(texto.count(l) for l in letras_comunes)

# Captura de paquetes ICMP
def capturar_paquete(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:  # Echo Request
        data = bytes(pkt[ICMP].payload)
        if len(data) >= 1:
            mensaje_cifrado.append(chr(data[0]))
            print("Mensaje cifrado parcial:", "".join(mensaje_cifrado))

# Ejecutar sniffer
print("Escuchando paquetes ICMP... presiona Ctrl+C para detener.")
try:
    sniff(filter="icmp", prn=capturar_paquete, store=False)
except KeyboardInterrupt:
    pass  # Salimos solo de la captura

# Reconstruir mensaje completo
mensaje_cifrado_str = "".join(mensaje_cifrado)
print("\nMensaje cifrado completo:", mensaje_cifrado_str)

# Descifrar todas las combinaciones César
print("\n=== Descifrados posibles (César 1 a 26) ===")
candidatos = []
for clave in range(1, 27):
    descifrado = descifrar_cesar(mensaje_cifrado_str, clave)
    score = score_frecuencia(descifrado)
    candidatos.append((score, clave, descifrado))

# Seleccionar la mejor opción según frecuencia
mejor = max(candidatos, key=lambda x: x[0])

# Mostrar resultados
for score, clave, desc in candidatos:
    if clave == mejor[1]:
        print(Fore.GREEN + f"[{clave:2}] {desc}" + Style.RESET_ALL)
    else:
        print(f"[{clave:2}] {desc}")