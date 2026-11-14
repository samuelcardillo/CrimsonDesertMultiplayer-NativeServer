# Prueba en vivo con dos copias, automatizada (14-nov-2026, build 1.0.0.3663)

Lo que se usó la noche del 14-nov para probar el barco sin nadie al teclado. Todo es solo lectura de memoria más
entrada de teclado y ratón a la ventana del juego. `python -I`, Git Bash y `pwsh`. Antes: Steam abierto, las dos copias
cerradas (el lanzador hace copia de las partidas en `backups/saves-2inst-*`).

- `ui.ps1 -GamePid <pid> -Do shot|key|hold|look|click|lmb|mmb|wheel|drag ...`: entrada solo a la ventana de ese proceso
  (comprueba que está delante antes de mandar nada) y capturas (`-Out`; `UI_CROP=x,y,w,h` recorta a resolución real).
  **No manda ALT si la ventana ya está delante:** hasta el 14-nov mandaba un toque de ALT en cada acción, y el
  personaje seguía corriendo tras un W corto.
- `cdbuild.py`: el slot del mundo y el de la cámara de la build instalada (3576 o 3663).
- `posnow.py pid`: posición del personaje propio ahora mismo (local a su padre si lo tiene, y la clave del padre).
- `face.py pid x z`: gira la cámara hacia un punto del mundo. `walk.py pid [-s parada] [-n pasos] x z [x z ...]`: anda
  a puntos del mundo con W cortos, leyendo la posición en vivo (vale nadando). `goto3576.py`: lo mismo, más rápido en
  tramos largos (corre), menos fiable cerca de obstáculos.
- `shiplocal.py pid lx lz ...`: puntos del sistema del barco (`0xB010000A`) → mundo. `shipwalk.py pid lx lz ...`: anda
  por la cubierta a puntos del sistema del barco (el barco amarrado gira: 36°, 47°, 66° en tres sesiones).
  `shipparts.py pid`: el árbol de piezas.
- `map_tp.py pid host|guest x z`: viaje rápido al nexo más cercano a un punto, por el mapa (usa `tp.sh` y `nexus.py`:
  doble clic en el icono del nexo y Espacio; `nexus.py` elige la mancha azul más cercana al punto, porque el punto
  azul del otro jugador en el mapa desviaba el clic). `mapcal.py pid host|guest`: con el mapa abierto, el punto del
  mundo del centro de la pantalla y la escala (dos pines). Al máximo de ampliación (0,04 m por píxel) el mapa enseña
  calles y plantas de edificios: sirve para sacar una ruta a pie.
- `launch_house.ps1` (cierra, despliega, lanza las dos copias y mete al anfitrión en el mundo) y `run_join.ps1 -Attach
  -AttachHost <h> -AttachGuest <g>` (une al invitado).
- `shipsession.sh [etapa] [H G]`: de cero a «anfitrión al timón, invitado en la cubierta de popa» (~25 min): lanzar,
  Vellua, Hopkins, sacar el barco (2600, no queda guardado), unir al invitado, subir los dos por la escala de babor.
  Etapas: `launch` (todo), `hopkins`, `join`, `guestboard`, `hostboard`. `hop.sh H`: solo apuntar a Hopkins y R.
- `shopsession.sh`: de cero a «el invitado compra una Water a Delkin y un saco en el puesto de al lado» (Hernand,
  ~25 min): lanzar, anfitrión al nexo de Hernand y a la calle de las tiendas, unir al invitado, llevarlo al
  mostrador, R, comprar, salir, y E mantenida en el puesto. No vende nada (vender exige mirar antes la pantalla).

## Lo que hay que saber

- **Hopkins (gestor de barcos de Vellua):** el aviso «R Manage Ship» sale en blanco solo desde
  (-10471,9, 352,5, -6138,1…-6138,3), con la cámara hacia (-10468, -6145) y `look -Dx 10 -Dy 20`; en gris o sobre el
  saco de trigo, R abre el mapa. No depende de la hora. R mantenida 2 s; Espacio, Espacio, Esc.
- **Barco amarrado:** origen ~(-10372, 350, -6207); escala de babor en local (-4,37, -0,74, -4,21): nadar a local
  (-9, -7,7), luego (-5,3, -4,3), mirar a (-3, -4,21) y W 3,5 s + 3 s. Cubierta: (-2,9, -1,2) → escalera (-2,85, 0,6)
  → cubierta de popa (-2,78, 2,27); timón en (0, 1,85): desde ahí, un paso hacia el timón y E. Al timón: LSHIFT 1,5 s
  = una marcha (3,4 m/s; dos, hasta 13 m/s), A/D giran, ALT frena. El barco encalla con facilidad al sur de Vellua.
- **Hernand:** nexo en (-10626,4, -3813,3). A Delkin (mostrador (-10655,4, -3877,2), mirar a (-10650,0, -3881,5))
  se va por el arco: (-10637,0, -3823,5) → (-10641,5, -3827,0) → (-10645,6, -3831,6) → (-10650,1, -3835,2) →
  (-10655,6, -3840,2) → (-10661,7, -3845,7) → (-10663,2, -3856,9) → (-10662,5, -3869,3). En línea recta desde el
  nexo se acaba encima del muro de un huerto. Puestos: junto a Delkin desde (-10653,9, -3876,4) mirando a
  (-10648, -3873) («Harvest Sack»), y el del almacén general desde (-10645,5, -3862,4) («Rosemary»). Delkin
  atiende también por la tarde (18:43 de juego). `run_join.ps1` puede decir «guest idle: False» con el invitado ya
  dentro: la prueba es `posnow.py`. El invitado aparece en su último nexo, no junto al anfitrión.
- La copia que no está delante va a ~7 fotogramas/s: las medidas de «un fotograma de retraso» en esa copia salen
  veinte veces peores que con ella delante.
- Medir: `tools/porting/boat/ridemon.py` (barco en las dos copias y el invitado en cubierta) y `passmon.py` (a qué
  distancia de su sitio dibuja cada cliente al otro jugador).
