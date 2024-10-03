# HomebridgeUIAPI
## HomebridgeUIAPI - Fhem Integration

HomebridgeUIAPI steuert die Homebridge UI

### update

`update add https://raw.githubusercontent.com/RP-Develop/HomebridgeUIAPI /main/controls_HomebridgeUIAPI .txt`

## 39_HomebridgeUIAPI.pm

`define <name> HomebridgeUIAPI  Host:Port Benutzername Password`

Beispiel: `define HomebridgeUIAPI  HomebridgeUIAPI  192.168.0.2:8581 username password`

Nach kurzer Zeit sollte eine Verbindung zur Homebridge UI aufgebaut sein.

Die Hilfe zu weiteren Funktionen, ist nach Installation in der Commandref zu finden.  
