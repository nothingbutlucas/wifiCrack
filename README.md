### Esta herramienta es un fork de un script que hizo [s4vitar](https://github.com/s4vitar/wifiCrack), adaptado a 2023, probado en Debian 12.

# wifi_crack.sh

## Dependencias

Si bien el script te automatiza la instalación de estas herramientas, te recomiendo que las instales por tu cuenta y que estén en tu PATH

- [gum](https://github.com/charmbracelet/gum)
- [hcxdumptool](https://github.com/ZerBea/hcxdumptool.git)
- [aircrack-ng](https://www.aircrack-ng.org/)
- [macchanger](https://github.com/alobbs/macchanger)
- [hashcat](https://hashcat.net/hashcat/)
- [tshark](https://tshark.dev/setup/install/)


## Instalación

```bash
git clone https://github.com/nothingbutlucas/wifiCrack
cd wifiCrack
chmod +x wifi_crack.sh
sudo ./wifi_crack.sh
```

## Mejoras con respecto a la versión de 2020

1. Actualización de **paquetes y programas** a sus respectivas versiones de **2023**.
2. **Compatibilidad** con distribuciones que manejan **apt, pacman, yum o dnf** cómo administrador de paquetes.
3. **Menú interactivo** para elegir la **tarjeta de red** haciendo uso del elegante **[gum](https://github.com/charmbracelet/gum)**.
4. **Compatibilidad** a la hora de **reiniciar** el **network-manager/NetworkManager** y el **wpa_supplicant**.
5. En vez de poner el nombre de la red en un ataque handshake, ponemos el **[bssid](https://es.wikipedia.org/wiki/BSSID)**. Esto nos permite ser **más precisos** y evitar tener que manejar los espacios y caracteres raros de algunas redes wifi.
6. En vez de usar una wordlist predeterminada, **elegís la tuya** en el momento de la ejecución.
7. En caso de que alguno de los 2 ataques fallen, **se pueden reintentar** dentro del flujo del mismo script.
8. En el ataque **PMKID** se pueden seleccionar los minutos de escaneo.
9. **Rotación de MAC Address** entre reintentos.
10. Uso de **[gum](https://github.com/charmbracelet/gum)** en el *renderizado* del texto, teniendo una UI más agradable y elegante.
11. No hace falta pasarle las flags de los ataques, se pueden **elegir de forma interactiva**.

## Cosas se mantienen del script original:

1. 2 modos de ataque: **PKMID y Handshake**
2. **Lógica** de los ataques

## TODO
[ ] - Soporte de ataque con 2 placas de red (Una de-autentica, la otra escucha)
[ ] - Añadir posibilidad de capturar pmkid haciendo un ataque de handshake
[ ] - Flag para saltarte la verificación de dependencias
[ ] - Soporte al inicio por falta de gum
[ ] - Agregar opción -y para automatizar el proceso de ataque
