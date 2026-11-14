#pragma once
// housing_trace (build 3576; 3663 sin portar, diagnóstico, solo observa): cuenta las llamadas a las funciones de vivienda del cliente
// (los métodos de pa::VHousingManager y las de sus registros) y registra las primeras de cada una con sus argumentos y
// quién la llamó. Sirve para encontrar qué función construye los muros de una casa al cargar su escenario.
#include <cstdint>
#include <string>

namespace cdmp::session2 {
// [session2] housing_trace = 0 (por defecto) | 1. Cualquier papel; pone sus ganchos desde su propio hilo cuando existe
// el WorldSystem (el invitado no pasa por el late init del anfitrión).
void housing_trace_start(bool on);
}  // namespace cdmp::session2
