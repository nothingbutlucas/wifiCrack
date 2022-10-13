### Esta herramienta es un fork de un script que hizo [s4vitar](https://github.com/s4vitar/wifiCrack), adaptado a 2022, probado con una distribución de fedora.

# wifi_crack.sh

## Mejoras con respecto a la version de 2020

1. Actualización de **paquetes y programas** a sus respectivas versiones de **2022**.
2. **Compatibilidad** con distribuciones que manejan **apt, pacman, yum o dnf** cómo administrador de paquetes.
3. **Menu interactivo** para elegir la **tarjeta de red** haciendo uso del elegante [select](https://linuxize.com/post/bash-select/) de bash.
4. **Compatibilidad** a la hora de **reiniciar** el **network-manager/NetworkManager** y el **wpa_supplicant**.
5. En vez de poner el nombre de la red en un ataque handshake, ponemos el [bssid](https://es.wikipedia.org/wiki/BSSID). Esto nos permite ser más precisos y evitar tener que manejar los espacios y caracteres raros de algunas redes wifi.
6. En vez de usar rockyou.txt estamos usando la [kaonashi para WiFiWPA](https://github.com/kaonashi-passwords/Kaonashi).
7. En caso de que alguno de los 2 ataques fallen, se pueden reintentar dentro del flujo del mismo script.
8. En el ataque **PMKID** se pueden seleccionar los minutos de escaneo.

## El resto de las cosas se mantienen del script original:

1. 2 modos de ataque: **PKMID y Handshake**
2. **Panel de ayuda** muy similar
3. **Lógica** de los ataques

```bash
Usage: ./wifi_crack.sh -a attack_mode
        a) Attack mode
        Available attack modes:
                PMKID
                Handshake
        h) Help panel
        Show this help panel

        Example: ./wifi_crack.sh -a PMKID

[-] Taking network card to monitor mode...
[+] Network card is now in managed mode.

[-] Restarting network manager...
[+] Network manager restarted.

[-] Exiting...
```

## Fallos y posibles futuras mejoras

1. Al seleccionar más de 1 minuto en el ataque pmkid el proceso crashea el sistema por completo y solo se puede reiniciar
2. Añadir la descarga o verificación de que kaonashi exista
