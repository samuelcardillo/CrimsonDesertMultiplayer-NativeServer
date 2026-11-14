# Launcher de jugadores (`cdmp_launcher.exe`)

Hecho el 2026-11-14. Instala o actualiza el mod en la carpeta del juego, arranca el juego con el mod o sin él y
escribe con quién se juega. No tiene código del juego ni ganchos: solo copia archivos, escribe `cdmp.ini` y lanza
`steam://rungameid/3321460`. Lo que ve el jugador está en inglés.

## Dónde está

| Qué | Archivo |
|---|---|
| Reglas, sin Windows (se prueban solas) | `tools/launcher/launcher_logic.h` |
| Archivos, registro, descarga | `tools/launcher/launcher_core.cpp` |
| Ventana (Dear ImGui sobre Direct3D 11) | `tools/launcher/main.cpp` |
| Pruebas | `tests/launcher_tests.cpp` (ctest `launcher`) |
| En el kit | `scripts/package_coop.ps1` mete el exe, `package.txt` y `kit/coop/cdmp_launcher.ini` |

Para probarlo sin tocar el juego real:
`cdmp_launcher.exe --game-dir <bin64 falso> --data-dir <carpeta> --bundle <carpeta del kit> --no-launch`.
Un `bin64` falso sirve con los primeros 4 KB del `CrimsonDesert.exe` real (de ahí lee la build).

## Qué hace

1. **Encuentra el juego**: `HKCU\Software\Valve\Steam\SteamPath` → `steamapps\libraryfolders.vdf` →
   `appmanifest_3321460.acf` → `<biblioteca>\steamapps\common\<installdir>\bin64`. Se puede elegir la carpeta a mano.
2. **Lee la build del juego**: el timestamp del PE (los primeros 4 KB del exe) y la versión del recurso de versión.
3. **Busca paquetes del mod**, en este orden: la dirección de actualizaciones, la carpeta del kit (donde está el
   exe) y las copias que guardó antes en `%LOCALAPPDATA%\cdmp_launcher\packages\<id>\`. Usa el primero que nombre la
   build instalada; si ninguno la nombra, un kit sin `package.txt` (los anteriores al launcher) se usa avisando de
   que no dice para qué build es. Si solo hay paquetes de otra build, no deja jugar con el mod y lo dice.
4. **Botón de jugar**:
   - *Join a friend* / *Host a game*: copia el paquete a su carpeta (comprobando el SHA-256 de cada archivo),
     instala `winmm.dll` y `cdmp.asi` en `bin64`, escribe `cdmp.ini` desde la plantilla del papel
     (`cdmp.ini.guest` / `cdmp.ini.host`) con `player_name` y `peer_steamid`, y lanza el juego por Steam.
   - *Single-player*: quita `cdmp.asi` y el cargador de `bin64` y lanza el juego. `cdmp.ini` se queda.
   - Con el juego abierto no escribe nada.
5. **Con quién**: el invitado elige al anfitrión (`peer_steamid`; vacío = el único amigo jugando). El anfitrión
   puede limitar quién entra (su `peer_steamid`; vacío = cualquier amigo jugando). La lista de nombres sale de la
   caché local de Steam (`userdata\<cuenta>\config\localconfig.vdf`, bloque `friends`): no dice quién está jugando
   y puede traer gente que no es amiga. También se puede pegar un SteamID64 o un enlace `/profiles/<id>`.

## Reglas que conviene conocer

- **`winmm.dll` ajeno no se toca.** Es "nuestro" si su SHA-256 es el del paquete o el que el launcher instaló antes
  (`installed_loader_sha256` en sus ajustes). Cualquier otro se deja, también al quitar el mod. Si hay otro `.asi`
  en `bin64`, `scripts\` o `plugins\`, nuestro cargador se queda al pasar a un jugador.
- **`cdmp.ini`**: el launcher marca su primera línea (`; cdmp_launcher role=… template=<sha256>`). Mismo papel y
  misma plantilla: solo cambia `player_name` y `peer_steamid`, lo que el jugador haya tocado se conserva. Otro papel
  u otra plantilla (kit nuevo): se reescribe desde la plantilla, porque los ajustes del kit se prueban en conjunto.
  El archivo anterior se guarda: `cdmp.ini.before-launcher` si era del jugador (una vez, nunca se pisa) o
  `cdmp.ini.bak` si era del launcher.
- **Nombre del jugador**: solo ASCII imprimible, sin comillas, 32 caracteres. El mod lee el ini en la página de
  códigos ANSI del PC.
- **Nombres de archivo de un paquete**: solo `winmm.dll`, `cdmp.asi`, `cdmp.ini.host` y `cdmp.ini.guest`. Una lista
  no puede hacer que el launcher escriba otra cosa.

## `package.txt` y las actualizaciones

El mismo texto describe un kit (lo genera `package_coop.ps1`) y una dirección de actualizaciones (una lista, el más
nuevo primero):

```
[package]
id=cdmp-coop-20261114-3663-v23
game=1.0.0.3663 0x6AF5D198
file=winmm.dll <sha256> [dónde]
file=cdmp.asi <sha256> [dónde]
file=cdmp.ini.host <sha256> [dónde]
file=cdmp.ini.guest <sha256> [dónde]
```

`[dónde]` es una dirección `https://` o una ruta relativa a la lista; sin él, el archivo está junto a la lista.
`game=` puede repetirse. Solo se descarga por https; una lista en la red no puede nombrar un archivo de este PC.

La dirección sale de los ajustes del jugador ("Updates from") o, si no puso ninguna, de `cdmp_launcher.ini` del kit
(`[update] address=`). Puede ser una dirección https o una carpeta compartida; si acaba en `/` o es una carpeta, se
lee su `package.txt`. **Hoy está vacía: no hay ningún sitio de descarga decidido.** Para publicar una versión basta
con subir el contenido de un kit (con su `package.txt`) y poner esa dirección en `kit/coop/cdmp_launcher.ini` antes
de empaquetar.

El SHA-256 protege de una descarga corrupta, no de un servidor comprometido: la lista viene del mismo sitio que los
archivos. Firmar la lista quedaría para más adelante.

## Comprobado y sin comprobar

Comprobado el 2026-11-14:
- `launcher` en ctest: reglas y trabajo con archivos sobre carpetas falsas en `%TEMP%`.
- En este PC, con la ventana real: encuentra el juego por Steam (1.0.0.3663) y reconoce el mod instalado; contra
  una copia falsa de `bin64` (`--game-dir`, `--no-launch`): instalar, `cdmp.ini` de invitado y de anfitrión, copia
  del ini anterior, conservar un cambio hecho a mano, elegir amigo pegando un SteamID64 o un enlace, quitar el mod.
- La descarga: una dirección https que contesta 404 y otra que contesta 200 (una página pública, no un paquete).

Sin comprobar:
- **Pulsar el botón contra el juego real y arrancarlo** (`steam://`), y una sesión jugada desde el launcher.
- Descargar un paquete de verdad por https (el mismo código que la carpeta compartida, que sí se prueba).
- Otro PC: otra escala de pantalla, Steam en otra ruta, SmartScreen o el antivirus con el exe sin firmar.

Fuera de esta primera versión: que el launcher se actualice a sí mismo, saber qué amigos están jugando ahora
(haría falta abrir la API de Steam con el AppID del juego desde el launcher: sin probar), y los pasos de después de
la sesión (`apply-guest-progress.ps1`, `host_save_restore.ps1`).
