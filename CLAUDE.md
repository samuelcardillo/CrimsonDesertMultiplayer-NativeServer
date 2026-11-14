# Crimson Desert Multiplayer — guía para Claude

Mod cooperativo para Crimson Desert (C++20, MSVC x64). Lee `docs/ESTADO-3527.md` para saber qué
funciona hoy, y `README.md` y `docs/ROADMAP.md` para el contexto. Casi toda la investigación de `docs/research/`
se escribió sobre la build 2976: sus direcciones no valen en 3527, pero las explicaciones sí.

## Contexto que no está en el código
- Documentación e investigación en español. Lo que ve o maneja un jugador va en inglés: el panel del juego, `kit/coop/`
  y los scripts del kit.
- **Pruebas con dos jugadores:**
  - Lo normal es desarrollar y hacer la primera prueba en un PC contra `cdmp_peer.exe` por loopback
    (rápido, un solo log con los dos lados).
  - Las pruebas de dos jugadores reales usan un segundo PC (con otra cuenta de Steam que tenga el juego)
    como **invitado** y el PC principal como **anfitrión**, conectados por Steam (`docs/PRUEBA-DOS-PC.md`).
    El invitado recibe el mod y devuelve sus logs por una carpeta compartida.
  - En un mismo PC **sí** se pueden ejecutar dos copias del juego (con la misma cuenta de Steam; en 3527 se juega
    así hasta el mundo, ver `tools/porting/configs/cdmp.3527-2inst-*.ini`). El `.exe` lanzado a mano se relanza a través de Steam,
    que rechaza una segunda copia; la segunda se lanza como lo hace Steam: variables de entorno
    `SteamAppId=3321460` y `SteamGameId=3321460`, y el argumento `PlatformServiceType=Steam`. Steam tiene que
    estar abierto (`scripts/launch-2inst.ps1`).
  - Para usarlo con el mod, cada copia necesita su propio papel, ini y log. Las dos comparten
    `%LOCALAPPDATA%\Pearl Abyss\CD\save`: separa las partidas del invitado y haz copia de seguridad antes de
    cargar ninguna partida. La prueba entre dos PC sigue siendo la final (red real, túnel por Steam, cargas
    a distinta velocidad).
- Juego: `D:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert.exe`,
  versión 1.0.0.3663 desde el 2026-11-13 (PE timestamp `0x6AF5D198`), portada esa noche (estático por módulos;
  en vivo: unión y vuelta; `docs/research/port-3663.md`). Base fija `0x140000000`. Cualquier offset o firma vale solo para su
  build; anota la build junto a cada hallazgo.
  El código admite también 3576 (`0x6AED2E85`), 3549 (`0x6AEB7D59`), 3527 (`0x6AEA07A6`; misma
  distribución que 3549 salvo la sección RWX: `Build::v3527` y `game::is_3549()`) y 2976 (`0x6AB28F00`) con tablas por build. Steam puede actualizar el juego en cualquier momento: si el mod se
  desactiva, compara con `python tools/porting/build_delta.py`.
- Las partidas están en `%LOCALAPPDATA%\Pearl Abyss\CD\save`. Haz una copia en
  `backups/` antes de cualquier prueba que **escriba** en la memoria del juego.
- `reference/` (fuera del repositorio) puede contener proyectos de terceros sin licencia, como
  CrimsonDesertCoop: úsalos solo como referencia y no copies su código. Su análisis está en
  `docs/ANALISIS-CrimsonDesertCoop.md`.

## Comandos
- Compilar y pasar tests: `.\scripts\build.ps1` (busca solo las VS Build Tools; cmake no está en el PATH).
- Instalar en el juego: `.\scripts\deploy.ps1`; desinstalar con `-Remove`. Falla si el juego está abierto.
- Si cambias `tools/porting/configs/cdmp.3527-2inst-*.ini`, regenera el kit de dos PC: `python tools/porting/make_steam_kit.py`.
- Launcher de jugadores (`cdmp_launcher.exe`, `docs/LAUNCHER.md`): instala el mod, lanza con o sin él y elige con quién.
  Para probarlo sin tocar el juego: `--game-dir <bin64 falso> --data-dir <carpeta> --bundle <kit> --no-launch`.
  `scripts\package_coop.ps1 -Suffix 3663-vNN` lo mete en el kit junto con `package.txt`.
- Prueba completa sin juego: arranca `cdmp_peer.exe` y luego `cdmp_host.exe <ruta\cdmp.asi> <segundos>`.
  `LoadLibrary` falla con rutas largas (error 206), así que usa `build\e2e\`.
- Prueba en el juego: arranca `cdmp_peer`, lanza `steam://rungameid/3321460` y lee `bin64\cdmp.log`.
  El juego ignora WM_CLOSE: si está en la pantalla de título, ciérralo con `Stop-Process`.
- Prueba automática con dos copias (`tools/porting/livetest/README.md`): `ui.ps1` (entrada solo a la ventana del
  juego), `walk.py` / `shipwalk.py` (andar leyendo la posición en vivo) y `shipsession.sh` (del arranque al anfitrión
  al timón con el invitado en cubierta). Hopkins (barco en Vellua) depende de la postura, no de la hora.

## Reglas de ingeniería
- Nada de inline hooks en direcciones que estén a mitad de una función. Para puntos
  de inyección de Cheat Engine usa `safetyhook::create_mid`.
- Cada lectura de memoria del juego tiene que estar protegida (`VirtualQuery`/SEH).
  Un crash del juego se envía a Pearl Abyss (sentry/crashpad).
- Nunca identifiques entidades entre PCs por su dirección de memoria.
- Nunca identifiques una sección del `.exe` por su nombre: el protector los cambia en cada build. Usa sus flags.
- No hagas trabajo dentro de `DllMain`: todo va en el hilo worker.
- El loader (`winmm.dll`) también carga en `crashpad_handler.exe`; `dllmain.cpp` filtra por el exe.
- Lo que falle en un `cdmp_crash*.dmp`: `python -I tools/porting/minidump_inspect.py <dmp> --out <json>`.
- Overlay: solo **hooks inline** (safetyhook) sobre funciones, nunca parches de
  vtable, porque Streamline llama a Present directamente. Instálalo **diferido**
  (tras `WorldSystem` y con la ventana visible): instalarlo al arrancar colgó el juego.
  Antes de probar en el juego, prueba con `cdmp_dx12_test.exe`.
- Para verificar visualmente, haz una captura con `System.Drawing CopyFromScreen`
  (pantalla 2560×1440) y recorta la zona de interés.
- El protocolo se serializa campo a campo (`protocol.cpp`); si cambia el formato, sube `kVersion`.
