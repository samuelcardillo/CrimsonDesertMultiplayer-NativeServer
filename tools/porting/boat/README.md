# Herramientas del barco (13-nov-2026, build 1.0.0.3576)

Diagnóstico del barco en cooperativo. Ver `docs/ESTADO-3527.md`, entrada «13-nov: BARCO, DIAGNÓSTICO».

- `shipscan.py captura.bin clave [desde_GB] [hasta_GB]`: `MoveActorReq` (2833) y `MoveActorAck` (3094) de una clave,
  por regex sobre la captura (segundos con capturas de varios GB). Pose de mundo en `+196`, sello en `+212`.
- `keyops.py captura.bin clave t_desde t_hasta`: todos los mensajes que nombran la clave en una ventana, por opcode.
- `opcount.py captura.bin t_desde t_hasta [ops]`: recuento por (dirección, opcode) en una ventana.
- `shipmem.py pid clave`, `comps.py pid clave`, `dumpobj.py pid dir tam`: lectura (solo lectura) del actor, su
  TransformSync y sus componentes con nombres RTTI (`tools/porting/data/rtti_3576.json`). Mundo en `exe+0x71C0100`.
- `hw_watch_ship.cpp`: DLL de diagnóstico. Punto de ruptura hardware de escritura (DR0) sobre la posición del barco en
  todos los hilos y un VEH; registra el sitio que escribe y, si la posición salta más de 30 m, la pila desenrollada. No
  llama a nada del juego; se quita sola (al cuarto salto, a los 50 min o con `shiptrace.stop` junto a la DLL). Se
  compila con `cl /LD /O2 /EHsc /std:c++20` y se carga en la copia del invitado con `inject.py pid ruta.dll`. Solo para
  pruebas en local; haz copia de las partidas antes.
- `hw_watch.cpp`: la misma DLL, genérica: `<dll>.cfg` con `dirección longitud sites|jump|req [x z sector]`; log
  compartido (se lee mientras corre). Con ella se encontraron el escritor por fotograma y la petición de tipo 7.
- `vehicle_follow_test.cpp`: el experimento que dio el arreglo (puntos de ruptura de EJECUCIÓN en los dos setters;
  cambia la pose de la petición de tipo 7 del vehículo por su pose de red). Ya no hace falta: es `session2/vehicle_follow`.
- `vfmon.py host guest clave segundos`: la pose del barco en las dos copias cada 0,5 s y la distancia.
  `vfmon3.py`: además el personaje del anfitrión respecto al barco (en el anfitrión su TS es local: no sirve allí).
- `vfreplay.py`: reproduce las muestras de red que recibió el invitado (captura) con la lógica de `vfl::Track` para
  varios retrasos y las compara con la pose real del anfitrión (su captura) unos ms antes.
- `vehcands.py pid`: los gimmicks de vehículo con padre (vtable, controlador, hijos). Así se vio (13-nov, noche) que
  los caballos de los establos llevan 8–12 cada uno y que la regla de v20 no era solo del barco.
- `vfmon5.py host guest segundos [periodo]`: el vehículo `0xB010000A` en las dos copias (posición, yaw, velocidad) y la
  distancia; la medida de la navegación de las 18:27.
- `shipparts.py pid`: el árbol de piezas que cuelgan de `0xB010000A`. `shiplocal.py pid lx lz ...`: un punto en el
  sistema del barco → mundo (para ir al timón o a la escalera con el barco en otra pose).

## 14-nov-2026 (build 1.0.0.3663): el timón, los pasajeros

Ver `docs/research/port-3663.md`, «Barco en 3663». Usan `../livetest/cdbuild.py` (slots de la build instalada).

- `tsprobe.py pid clave [s]`: el TransformSync de un actor: pose local, marco del padre, pose de mundo, y los tipos de
  petición pendientes vistos en `TS+0x5BC` al muestrear (así salieron el 7 de cerca, el 12 de lejos y el 12 de los
  personajes).
- `partlocal.py host guest`: la pose local de cada pieza del barco en las dos copias, lado a lado (el timón: 0,81 /
  0,29 en el anfitrión, 3,76 / 2,14 en el invitado). Cambia el rango de claves de la sesión dentro del script.
- `tsflags.py`, `hdiff.py host guest clave comp tam`: banderas del TS y volcado de un componente en las dos copias
  con las filas que difieren.
- `ptrpath.py pid desde hasta [prof]`: caminos de punteros de un objeto a otro (el objeto de escena de un actor:
  `[[comps+0x30]+0x18]-0x28`). `scenechain.py pid objeto`: la cadena de enganche de un objeto de escena y su
  transformación local (`+0x1D0`). `scenelocal.py host guest clave_min clave_max`: la local del objeto de escena de
  cada pieza junto a la del TS, en las dos copias.
- `keyscan.py captura.bin clave [t0 t1]`: todos los mensajes de una captura que nombran una clave, por dirección y
  opcode (nombres del `.log` hermano; vale para cualquier build).
- `ridemon.py host guest s [periodo]`: el vehículo en las dos copias y el personaje del invitado (padre y local).
  `passmon.py host guest clave_anfitrión clave_invitado s`: a cuánto de su sitio en el barco dibuja cada cliente al
  personaje del otro.
- `poke3f.py pid dirección x y z`: ESCRITURA de prueba de tres floats (con ella se vio que corregir la local del objeto
  de escena del timón se queda). Solo en la copia del invitado y con copia de las partidas.
- `hw_watch.cpp`: ahora guarda los registros en cada sitio y, en modo `sites`, el qword de `[rbp + x]` (cuarto número
  del `.cfg`): con `696` (0x2B8) da el objeto de escena dentro del tick del TransformSync `0xB3A3B0`.
- `parents.py captura.bin clave`: qué padres nombran los `MoveActorReq` / `MoveActorAck` de un actor, por dirección (así
  se vio que el servidor solo conserva el padre «soporte del timón» y manda en blanco los de cubierta). `ackdump.py`:
  un `MoveActorAck` con padre y otro sin él, campo a campo. `../livetest/shipinv.py pid [x z]`: pose del barco y un
  punto del mundo en su sistema.
