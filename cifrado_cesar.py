def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():  # Solo aplica a letras
            base = ord('A') if caracter.isupper() else ord('a')
            # Fórmula de desplazamiento
            resultado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            # No modifica espacios ni signos
            resultado += caracter
    return resultado

def descifrado_cesar(texto, desplazamiento):
    return cifrado_cesar(texto, -desplazamiento)

# Ejemplo de uso:
mensaje = input("Ingrese el mensaje a cifrar: ")
clave = input("Ingrese la clave de desplazamiento (número): ")
clave = int(clave)

cifrado = cifrado_cesar(mensaje, clave)
descifrado = descifrado_cesar(cifrado, clave)

print("Texto original: ", mensaje)
print("Texto cifrado:  ", cifrado)
print("Texto descifrado:", descifrado)