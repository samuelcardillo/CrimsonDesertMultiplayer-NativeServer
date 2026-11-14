#pragma once
// housing_redraw (builds 3576 y 3663 (estático), invitado, EXPERIMENTAL): cuando llega la última parte de un 2733 en vivo (la casa que el
// anfitrión acaba de editar, housing_share_edits=1) y el invitado está en la etapa de esa casa, pide al juego que la
// vuelva a construir (0x461A60, la misma reconstrucción de la etapa activa que usa el cliente), para que los muros
// cambiados se vean sin volver a entrar.

namespace cdmp::session2 {
// [session2] housing_redraw = 0 (por defecto) | 1, invitado. Pone su gancho desde su propio hilo cuando existe el
// WorldSystem.
// [session2] housing_gimmick_guard = 0 (por defecto) | 1, invitado: con la casa del anfitrión como propia y sus registros
// de gimmicks enteros, el invitado no hace la parte de dueño de esos gimmicks (ranura 35 de pa::VHousingManager,
// 0x462DD0), que se caía al abrir el anfitrión el modo de construcción.
void housing_redraw_start(bool redraw, bool gimmick_guard);
}  // namespace cdmp::session2
