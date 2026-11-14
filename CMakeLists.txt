cmake_minimum_required(VERSION 3.24)
project(CrimsonDesertMultiplayer VERSION 0.0.1 LANGUAGES CXX)

if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Build with MSVC for x64 (the game is 64-bit Windows only). Use scripts/build.ps1.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT: the .asi must not depend on whichever runtime the game ships.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00
                        CDMP_VERSION="${PROJECT_VERSION}")
add_compile_options(/permissive- /utf-8 /EHsc /Zi)
add_link_options(/DEBUG)

# Strict warnings for our own code only (third-party code keeps its defaults).
function(cdmp_strict target)
    target_compile_options(${target} PRIVATE /W4)
endfunction()

# --------------------------------------------------------------- third party
include(FetchContent)
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.92.9b
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(imgui)

# Inline hooks with proper trampolines (Zydis disassembler, fetched too).
set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "" FORCE)
FetchContent_Declare(safetyhook
    GIT_REPOSITORY https://github.com/cursey/safetyhook.git
    GIT_TAG        v0.7.0
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(safetyhook)
# P8 review of 10-10, I4 (docs/research/pendientes/p8-revision-noche.md, "Correcciones"): safetyhook's
# trap handler retried any access violation on a page it had ever patched, forever. The library is
# built with third_party/safetyhook-patch/os.windows.cpp (upstream v0.7.0's file with that handler
# fixed; the diff is os.windows.cpp.patch next to it) in place of src/os.windows.cpp. The fetched tree
# is never modified, so a clean configure reproduces it; if the upstream file changes (another
# GIT_TAG), the configure stops here until the copy is redone from the new file.
set(CDMP_SAFETYHOOK_OS_SHA256 21d13961ade449678263a119f6a005cda214815814cbeffe30af2c00e37e0609)
file(READ ${safetyhook_SOURCE_DIR}/src/os.windows.cpp _sh_os)
string(REPLACE "\r\n" "\n" _sh_os "${_sh_os}")
string(SHA256 _sh_os_hash "${_sh_os}")
if(NOT _sh_os_hash STREQUAL CDMP_SAFETYHOOK_OS_SHA256)
    message(FATAL_ERROR "safetyhook's src/os.windows.cpp is not the v0.7.0 file the patched copy in "
                        "third_party/safetyhook-patch was made from (SHA-256 ${_sh_os_hash}); redo the copy")
endif()
# P8 session 26 (docs/research/s25/montura-regresion.md, sections 5 and 7.1): safetyhook's search for trampoline
# memory near a target gave up on free runs that do not start on a 64 KB boundary and stopped after one refused
# attempt below the target, so the host's first inline hook in the game's exe sometimes got the 14-byte fallback
# and was refused. The library is built with third_party/safetyhook-patch/allocator.cpp (upstream v0.7.0's file
# with allocate_nearby_memory fixed; the diff is allocator.cpp.patch next to it) in place of src/allocator.cpp,
# under the same SHA-256 rule as os.windows.cpp.
set(CDMP_SAFETYHOOK_ALLOCATOR_SHA256 dec1a65f3e0ab7cbd0ce9a39f5b5d7caeb646017d30888b8af472f74ee31bb5a)
file(READ ${safetyhook_SOURCE_DIR}/src/allocator.cpp _sh_alloc)
string(REPLACE "\r\n" "\n" _sh_alloc "${_sh_alloc}")
string(SHA256 _sh_alloc_hash "${_sh_alloc}")
if(NOT _sh_alloc_hash STREQUAL CDMP_SAFETYHOOK_ALLOCATOR_SHA256)
    message(FATAL_ERROR "safetyhook's src/allocator.cpp is not the v0.7.0 file the patched copy in "
                        "third_party/safetyhook-patch was made from (SHA-256 ${_sh_alloc_hash}); redo the copy")
endif()
get_target_property(_sh_sources safetyhook SOURCES)
list(TRANSFORM _sh_sources REPLACE "^(.*/)?src/os\\.windows\\.cpp$"
     "${CMAKE_SOURCE_DIR}/third_party/safetyhook-patch/os.windows.cpp" OUTPUT_VARIABLE _sh_patched)
if(_sh_patched STREQUAL _sh_sources)
    message(FATAL_ERROR "safetyhook: src/os.windows.cpp not found in the target's sources; patch not applied")
endif()
list(TRANSFORM _sh_patched REPLACE "^(.*/)?src/allocator\\.cpp$"
     "${CMAKE_SOURCE_DIR}/third_party/safetyhook-patch/allocator.cpp" OUTPUT_VARIABLE _sh_patched2)
if(_sh_patched2 STREQUAL _sh_patched)
    message(FATAL_ERROR "safetyhook: src/allocator.cpp not found in the target's sources; patch not applied")
endif()
set_property(TARGET safetyhook PROPERTY SOURCES ${_sh_patched2})

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx12.cpp
)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)
target_compile_definitions(imgui PUBLIC IMGUI_DISABLE_OBSOLETE_FUNCTIONS)
target_link_libraries(imgui PUBLIC d3d12 dxgi d3dcompiler)

# ------------------------------------------------------------------ our code
# Shared by the mod and the tools: wire protocol, UDP, session logic.
add_library(cdmp_common STATIC
    src/common/pattern.cpp
    src/common/protocol.cpp
    src/common/udp.cpp
    src/common/client_session.cpp
    src/common/reliable.cpp
    src/common/send_gate.cpp
    src/common/troc_frame.cpp
    src/common/native_opcode.cpp
    src/common/lz_block.cpp
    src/common/capture_file.cpp
    src/common/save_guard.cpp
    src/common/troc_script.cpp
    src/common/troc_link.cpp
)
cdmp_strict(cdmp_common)
target_include_directories(cdmp_common PUBLIC src)
target_link_libraries(cdmp_common PUBLIC ws2_32)

# The mod: cdmp.asi, loaded by Ultimate ASI Loader inside the game.
# The build id the two players compare when they connect: the first 8 hex
# digits of the commit (0 outside git), plus whether there were local changes.
set(CDMP_GIT_HASH 00000000)
set(CDMP_GIT_DIRTY 0)
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short=8 HEAD WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                    OUTPUT_VARIABLE _hash OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET RESULT_VARIABLE _rc)
    if(_rc EQUAL 0 AND _hash MATCHES "^[0-9a-f]+$")
        set(CDMP_GIT_HASH ${_hash})
    endif()
    execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain --untracked-files=no -- src
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_VARIABLE _dirty ERROR_QUIET)
    if(NOT _dirty STREQUAL "")
        set(CDMP_GIT_DIRTY 1)
    endif()
endif()
configure_file(cmake/build_id.h.in ${CMAKE_BINARY_DIR}/generated/build_id.h)

add_library(cdmp_mod SHARED
    src/mod/dllmain.cpp
    src/mod/mod.cpp
    src/mod/log.cpp
    src/mod/config.cpp
    src/mod/bg_speed.cpp
    src/mod/game/safe_memory.cpp
    src/mod/game/player_reader.cpp
    src/mod/game/camera_reader.cpp
    src/mod/game/rtti.cpp
    src/mod/net/troc_sniffer.cpp
    src/mod/net/local_capture.cpp
    src/mod/net/remote_puppet.cpp
    src/mod/net/puppet_minimap.cpp
    src/mod/net/horse_diag.cpp
    src/mod/net/aggro_test.cpp
    src/mod/net/enemy_relay.cpp
    src/mod/net/player_hits.cpp
    src/mod/net/piece4_test.cpp
    src/mod/net/guest_hits.cpp
    src/mod/net/attack_probe.cpp
    src/mod/net/coop.cpp
    src/mod/game/actor_lookup.cpp
    src/mod/game/game_errors.cpp
    src/mod/game/game_fault.cpp
    src/mod/game/hook_prepare.cpp
    src/mod/net/steam_transport.cpp
    src/mod/render/dx12_hook.cpp
    src/mod/render/hud.cpp
    src/mod/session2/child_hold.cpp
    src/mod/session2/clock_gate.cpp
    src/mod/session2/clock_push.cpp
    src/mod/session2/weather_sync.cpp
    src/mod/session2/catch_seq.cpp
    src/mod/session2/remote_rope.cpp
    src/mod/session2/rope_probe.cpp
    src/mod/session2/tree_bend.cpp
    src/mod/session2/docked_gimmicks.cpp
    src/mod/session2/interact_gate.cpp
    src/mod/session2/store_gate.cpp
    src/mod/session2/vehicle_follow.cpp
    src/mod/session2/shop_ui_trace.cpp
    src/mod/session2/guest_shop_window.cpp
    src/mod/session2/housing_share.cpp
    src/mod/session2/guest_shop_branch.cpp
    src/mod/session2/companion_probe.cpp
    src/mod/session2/field_share.cpp
    src/mod/session2/interaction_condition.cpp
    src/mod/session2/remote_visible.cpp
    src/mod/session2/guest_lifecycle.cpp
    src/mod/session2/identity_fix.cpp
    src/mod/session2/identity_probe.cpp
    src/mod/session2/report_guard.cpp
    src/mod/session2/save_hooks.cpp
    src/mod/session2/host_save_export.cpp
    src/mod/session2/session2.cpp
    src/mod/session2/server.cpp
    src/mod/session2/guest.cpp
    src/mod/session2/guest_actor_diag.cpp
    src/mod/session2/guest_reload_wait.cpp
    src/mod/session2/guest_diag_worker.cpp
    src/mod/session2/guest_s3.cpp
    src/mod/session2/guest_stage_diag.cpp
    src/mod/session2/p8_probes.cpp
    src/mod/session2/observer_stage.cpp
    src/mod/session2/observer_milestone.cpp
    src/mod/session2/observer_scene_copy.cpp
    src/mod/session2/observer_hold_acks.cpp
    src/mod/session2/load_trip.cpp
    src/mod/session2/slot_refresh.cpp
    src/mod/session2/ui_pause.cpp
    src/mod/session2/achievement_guard.cpp
    src/mod/session2/field_leave_guard.cpp
    src/mod/session2/focus_follow.cpp
    src/mod/session2/manager_probe.cpp
    src/mod/session2/pivot_guard.cpp
    src/mod/session2/ride_null_guard.cpp
    src/mod/session2/seq_marker.cpp
    src/mod/session2/user2_funnels.cpp
    src/mod/session2/fast_travel.cpp
    src/mod/session2/travel_probe.cpp
    src/mod/session2/remote_motion.cpp
    src/mod/session2/remote_interp.cpp
    src/mod/session2/horse_follow.cpp
    src/mod/session2/attach_follow.cpp
    src/mod/session2/ride_filter.cpp
    src/mod/session2/mount_sync.cpp
    src/mod/session2/combat_follow.cpp
    src/mod/session2/host_scene_diag.cpp
    src/mod/session2/guest_scene_diag.cpp
    src/mod/session2/observer_seq_copy.cpp
    src/mod/session2/guest_seq_route.cpp
    src/mod/session2/guest_seq_foreign.cpp
    src/mod/session2/guest_seq_present.cpp
    src/mod/session2/guest_bodyanim_diag.cpp
    src/mod/session2/guest_sched_bind.cpp
    src/mod/session2/guest_seq_play.cpp
    src/mod/session2/guest_sched_load.cpp
    src/mod/session2/owner_fanout.cpp
    src/mod/session2/guest_seq_restore.cpp
    src/mod/session2/guest_x_veto.cpp
    src/mod/session2/guest_x_interaction.cpp
    src/mod/session2/shop_probe.cpp
    src/mod/session2/shop_trade_probe.cpp
    src/mod/session2/observer_hold_scene_order.cpp
    src/mod/session2/npc_action_probe.cpp
    src/mod/session2/npc_probe_client.cpp
    src/mod/session2/enemy_damage_probe.cpp
    src/mod/session2/door_trace.cpp
    src/mod/session2/housing_redraw.cpp
    src/mod/session2/housing_trace.cpp
    src/mod/session2/scene_level_share.cpp
    src/mod/session2/user2_stages.cpp
    src/mod/session2/user2_shops.cpp
    src/mod/session2/freeze_watchdog.cpp
    src/mod/session2/guest_save_host.cpp
    src/mod/session2/guest_save_tunnel.cpp
    src/mod/session2/guest_save_guest.cpp
    src/mod/session2/world_anchor.cpp
)
cdmp_strict(cdmp_mod)
target_link_libraries(cdmp_mod PRIVATE cdmp_common imgui safetyhook::safetyhook)
target_include_directories(cdmp_mod PRIVATE ${CMAKE_BINARY_DIR}/generated)
set_target_properties(cdmp_mod PROPERTIES OUTPUT_NAME "cdmp" PREFIX "" SUFFIX ".asi")

# Tools for single-PC development.
add_executable(cdmp_peer tools/peer_sim/main.cpp tools/peer_sim/replay.cpp tools/peer_sim/save_sim.cpp)
cdmp_strict(cdmp_peer)
target_link_libraries(cdmp_peer PRIVATE cdmp_common)

add_executable(cdmp_host tools/host/main.cpp)
cdmp_strict(cdmp_host)

# D3D12 window that loads the mod, to test the overlay hook without the game.
add_executable(cdmp_dx12_test tools/dx12_test/main.cpp)
cdmp_strict(cdmp_dx12_test)
target_link_libraries(cdmp_dx12_test PRIVATE d3d12 dxgi)

# Read-only external memory inspector (hito 1).
add_executable(cdmp_probe tools/probe/main.cpp tools/probe/process.cpp)
cdmp_strict(cdmp_probe)
target_include_directories(cdmp_probe PRIVATE tools)
target_link_libraries(cdmp_probe PRIVATE cdmp_common)

# The players' launcher (docs/LAUNCHER.md): installs or updates the mod in the game folder, starts the game with or
# without it and writes who to play with. Its own Dear ImGui window on Direct3D 11; no game code and no hooks.
add_executable(cdmp_launcher WIN32
    tools/launcher/main.cpp
    tools/launcher/launcher_core.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)
set_source_files_properties(tools/launcher/main.cpp tools/launcher/launcher_core.cpp PROPERTIES COMPILE_OPTIONS /W4)
target_include_directories(cdmp_launcher PRIVATE src tools/launcher)
target_link_libraries(cdmp_launcher PRIVATE imgui d3d11 winhttp version shell32 ole32 advapi32)

# Opt-in external diagnostic capture for failures that bypass in-process handlers.
add_executable(cdmp_debug_watch EXCLUDE_FROM_ALL tools/porting/debug_watch.cpp)
cdmp_strict(cdmp_debug_watch)
target_link_libraries(cdmp_debug_watch PRIVATE dbghelp)

# Tests.
enable_testing()
# The launcher's rules and its work on files, against fake kit, game and data folders in %TEMP%.
add_executable(cdmp_tests_launcher tests/launcher_tests.cpp tools/launcher/launcher_core.cpp)
cdmp_strict(cdmp_tests_launcher)
target_include_directories(cdmp_tests_launcher PRIVATE src tools/launcher)
target_link_libraries(cdmp_tests_launcher PRIVATE winhttp version shell32 advapi32)
target_compile_definitions(cdmp_tests_launcher PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME launcher COMMAND cdmp_tests_launcher)
add_executable(cdmp_tests tests/tests.cpp)
cdmp_strict(cdmp_tests)
target_link_libraries(cdmp_tests PRIVATE cdmp_common)
add_test(NAME unit COMMAND cdmp_tests)
add_executable(cdmp_tests_native_opcode tests/native_opcode_tests.cpp)
cdmp_strict(cdmp_tests_native_opcode)
target_link_libraries(cdmp_tests_native_opcode PRIVATE cdmp_common)
add_test(NAME native_opcode COMMAND cdmp_tests_native_opcode)
# Option D (docs/OPCION-D-EMULADOR.md): the parts that do not need the game.
add_executable(cdmp_tests_optd tests/optd_tests.cpp)
cdmp_strict(cdmp_tests_optd)
target_link_libraries(cdmp_tests_optd PRIVATE cdmp_common)
target_compile_definitions(cdmp_tests_optd PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd COMMAND cdmp_tests_optd)
# The save guard's real KernelBase hooks, against a fake save folder in %TEMP%.
add_executable(cdmp_tests_optd_hooks tests/optd_hook_tests.cpp src/mod/session2/save_hooks.cpp
               src/mod/session2/host_save_export.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_hooks)
target_link_libraries(cdmp_tests_optd_hooks PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_hooks COMMAND cdmp_tests_optd_hooks)
# The same hooks with save_guard=trace (session 24): nothing refused, every operation logged.
add_executable(cdmp_tests_optd_hooks_trace tests/optd_hook_trace_tests.cpp src/mod/session2/save_hooks.cpp
               src/mod/session2/host_save_export.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_hooks_trace)
target_link_libraries(cdmp_tests_optd_hooks_trace PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_hooks_trace COMMAND cdmp_tests_optd_hooks_trace)
# The same hooks with save_guard=redirect (session 24): the trace's autosave lands in a sandbox copy of the folder.
add_executable(cdmp_tests_optd_hooks_redirect tests/optd_hook_redirect_tests.cpp src/mod/session2/save_hooks.cpp
               src/mod/session2/host_save_export.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_hooks_redirect)
target_link_libraries(cdmp_tests_optd_hooks_redirect PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_hooks_redirect COMMAND cdmp_tests_optd_hooks_redirect)
set_tests_properties(optd_hooks_redirect PROPERTIES TIMEOUT 120)
# Two copies on one PC (docs/research/dos-instancias.md): CDMP_ROLE=guest's redirect of ...\CD\save to
# ...\CD\save_cdmp_guest with the same hooks; the real folder is checked byte for byte by a child process.
add_executable(cdmp_tests_optd_guest_role tests/optd_guest_role_tests.cpp src/mod/session2/save_hooks.cpp
               src/mod/session2/host_save_export.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_guest_role)
target_link_libraries(cdmp_tests_optd_guest_role PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_guest_role COMMAND cdmp_tests_optd_guest_role)
set_tests_properties(optd_guest_role PROPERTIES TIMEOUT 120)
# The same: CDMP_ROLE's parsing, the ini choice, the role-tagged file names and three processes' logs in one folder.
add_executable(cdmp_tests_optd_two_inst tests/optd_two_inst_tests.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_two_inst)
target_link_libraries(cdmp_tests_optd_two_inst PRIVATE cdmp_common)
add_test(NAME optd_two_inst COMMAND cdmp_tests_optd_two_inst)
set_tests_properties(optd_two_inst PROPERTIES TIMEOUT 120)
# The same: scripts/launch-2inst.ps1 -NoLaunch against fake folders in %TEMP% (LOCALAPPDATA redirected).
add_test(NAME launch_2inst_script
         COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_SOURCE_DIR}/tests/launch_2inst_tests.ps1")
set_tests_properties(launch_2inst_script PROPERTIES TIMEOUT 300)
# Two copies on one PC, background_full_speed (bg_speed_logic.h): the gate, the foreground classification, the GPU
# class decisions over focus switches, the fallback when a class is refused and the give-up cap; plus, informative,
# whether this PC accepts the High GPU scheduling class for this test process without admin (set back afterwards).
add_executable(cdmp_tests_optd_bg_speed tests/optd_bg_speed_tests.cpp)
cdmp_strict(cdmp_tests_optd_bg_speed)
target_include_directories(cdmp_tests_optd_bg_speed PRIVATE src)
add_test(NAME optd_bg_speed COMMAND cdmp_tests_optd_bg_speed)
# P8 session 35, phase E (host_save_logic.h / host_save_export.h): host_save modes (real refused), slot whitelist,
# generation names, retention (never the newest valid), the rebuild plan when an export fails, manifest and journal
# round trips, the per-slot probe verdicts, and the archive itself on fake folders in %TEMP% (no hooks, no game).
add_executable(cdmp_tests_optd_host_save tests/optd_host_save_tests.cpp src/mod/session2/host_save_export.cpp
               src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_host_save)
target_link_libraries(cdmp_tests_optd_host_save PRIVATE cdmp_common)
add_test(NAME optd_host_save COMMAND cdmp_tests_optd_host_save)
set_tests_properties(optd_host_save PROPERTIES TIMEOUT 120)
# Review of phase E, M3: scripts/host_save_restore.ps1 against a fake save folder in %TEMP% (LOCALAPPDATA redirected).
add_test(NAME host_save_restore_script
         COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_SOURCE_DIR}/tests/host_save_restore_tests.ps1")
set_tests_properties(host_save_restore_script PROPERTIES TIMEOUT 300)
# P8 review I4: safetyhook's trap handler as built here (third_party/safetyhook-patch): a fault on a patched
# page that is not a patch in progress reaches the caller (upstream retried it forever; the watchdog ends a hang).
add_executable(cdmp_tests_optd_hook_traps tests/optd_hook_trap_tests.cpp)
cdmp_strict(cdmp_tests_optd_hook_traps)
target_include_directories(cdmp_tests_optd_hook_traps PRIVATE src)
target_link_libraries(cdmp_tests_optd_hook_traps PRIVATE safetyhook::safetyhook)
add_test(NAME optd_hook_traps COMMAND cdmp_tests_optd_hook_traps)
set_tests_properties(optd_hook_traps PROPERTIES TIMEOUT 60)
# P8 session 26 (docs/research/s25/montura-regresion.md, sections 5 and 7.1): safetyhook's search for trampoline
# memory near a target as built here (third_party/safetyhook-patch/allocator.cpp) against upstream's logic, on
# synthetic address-space layouts reserved in the test process; and hook_prepare's retry rule.
add_executable(cdmp_tests_optd_hook_near tests/optd_hook_near_tests.cpp src/mod/game/hook_prepare.cpp
               src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_hook_near)
target_link_libraries(cdmp_tests_optd_hook_near PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_hook_near COMMAND cdmp_tests_optd_hook_near)
set_tests_properties(optd_hook_near PROPERTIES TIMEOUT 120)
# RPT-0 K1: the error-report cut, on a fake reporter with the game's signature.
add_executable(cdmp_tests_optd_report tests/optd_report_tests.cpp src/mod/session2/report_guard.cpp
    src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_report)
target_link_libraries(cdmp_tests_optd_report PRIVATE cdmp_common safetyhook::safetyhook)
# The hook must go on the fake's body, not on an incremental-link jmp thunk.
target_link_options(cdmp_tests_optd_report PRIVATE /INCREMENTAL:NO)
add_test(NAME optd_report COMMAND cdmp_tests_optd_report)
# E3b: the field-sharing logic on fake game memory.
add_executable(cdmp_tests_optd_field tests/optd_field_tests.cpp src/mod/session2/field_share.cpp
    src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_field)
target_link_libraries(cdmp_tests_optd_field PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_field COMMAND cdmp_tests_optd_field)
# 3527 null-condition regression, with an optional replay of the installed
# executable's serializer bytes in this isolated test process.
add_executable(cdmp_tests_optd_interaction_condition tests/optd_interaction_condition_tests.cpp
    src/mod/session2/interaction_condition.cpp src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_interaction_condition)
target_link_libraries(cdmp_tests_optd_interaction_condition PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_interaction_condition COMMAND cdmp_tests_optd_interaction_condition)
add_executable(cdmp_tests_optd_character_phase tests/optd_character_phase_tests.cpp src/mod/game/safe_memory.cpp)
cdmp_strict(cdmp_tests_optd_character_phase)
target_include_directories(cdmp_tests_optd_character_phase PRIVATE src)
add_test(NAME optd_character_phase COMMAND cdmp_tests_optd_character_phase)
add_executable(cdmp_tests_optd_docking_dedupe tests/optd_docking_dedupe_tests.cpp)
cdmp_strict(cdmp_tests_optd_docking_dedupe)
target_include_directories(cdmp_tests_optd_docking_dedupe PRIVATE src)
add_test(NAME optd_docking_dedupe COMMAND cdmp_tests_optd_docking_dedupe)

add_executable(cdmp_tests_optd_gimmick_interact tests/optd_gimmick_interact_tests.cpp)
cdmp_strict(cdmp_tests_optd_gimmick_interact)
target_include_directories(cdmp_tests_optd_gimmick_interact PRIVATE src)
add_test(NAME optd_gimmick_interact COMMAND cdmp_tests_optd_gimmick_interact)

add_executable(cdmp_tests_optd_guest_shop_branch tests/optd_guest_shop_branch_tests.cpp)
cdmp_strict(cdmp_tests_optd_guest_shop_branch)
target_include_directories(cdmp_tests_optd_guest_shop_branch PRIVATE src)
add_test(NAME optd_guest_shop_branch COMMAND cdmp_tests_optd_guest_shop_branch)
add_executable(cdmp_tests_optd_housing_share tests/optd_housing_share_tests.cpp)
cdmp_strict(cdmp_tests_optd_housing_share)
target_include_directories(cdmp_tests_optd_housing_share PRIVATE src)
add_test(NAME optd_housing_share COMMAND cdmp_tests_optd_housing_share)
add_executable(cdmp_tests_optd_vehicle_follow tests/optd_vehicle_follow_tests.cpp)
cdmp_strict(cdmp_tests_optd_vehicle_follow)
target_include_directories(cdmp_tests_optd_vehicle_follow PRIVATE src)
add_test(NAME optd_vehicle_follow COMMAND cdmp_tests_optd_vehicle_follow)

add_executable(cdmp_tests_optd_achievement_guard tests/optd_achievement_guard_tests.cpp)
cdmp_strict(cdmp_tests_optd_achievement_guard)
target_include_directories(cdmp_tests_optd_achievement_guard PRIVATE src)
add_test(NAME optd_achievement_guard COMMAND cdmp_tests_optd_achievement_guard)

add_executable(cdmp_tests_optd_field_leave_guard tests/optd_field_leave_guard_tests.cpp)
cdmp_strict(cdmp_tests_optd_field_leave_guard)
target_include_directories(cdmp_tests_optd_field_leave_guard PRIVATE src)
add_test(NAME optd_field_leave_guard COMMAND cdmp_tests_optd_field_leave_guard)

add_executable(cdmp_tests_optd_focus_follow tests/optd_focus_follow_tests.cpp)
cdmp_strict(cdmp_tests_optd_focus_follow)
target_include_directories(cdmp_tests_optd_focus_follow PRIVATE src)
add_test(NAME optd_focus_follow COMMAND cdmp_tests_optd_focus_follow)

add_executable(cdmp_tests_optd_pivot_guard tests/optd_pivot_guard_tests.cpp)
cdmp_strict(cdmp_tests_optd_pivot_guard)
target_include_directories(cdmp_tests_optd_pivot_guard PRIVATE src)
add_test(NAME optd_pivot_guard COMMAND cdmp_tests_optd_pivot_guard)
add_executable(cdmp_tests_optd_seq_marker tests/optd_seq_marker_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_marker)
target_include_directories(cdmp_tests_optd_seq_marker PRIVATE src)
add_test(NAME optd_seq_marker COMMAND cdmp_tests_optd_seq_marker)
# P-RELOJ: the clock gate's logic on fake game memory.
add_executable(cdmp_tests_optd_clock tests/optd_clock_tests.cpp src/mod/session2/clock_gate.cpp
    src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_clock)
target_link_libraries(cdmp_tests_optd_clock PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_clock COMMAND cdmp_tests_optd_clock)
# P8 session 25 (clock_push_logic.h): the 2816 payload, the T2 state machine and W1's predicate (pure).
add_executable(cdmp_tests_optd_clock_push tests/optd_clock_push_tests.cpp)
cdmp_strict(cdmp_tests_optd_clock_push)
target_link_libraries(cdmp_tests_optd_clock_push PRIVATE cdmp_common)
add_test(NAME optd_clock_push COMMAND cdmp_tests_optd_clock_push)
# P8 session 25 weather (weather_sync_logic.h): the field table, the state-12 frame, sanity, interpolation, the gates,
# the owned-X records, the selftest machine, the modes and the lock-free double buffer (two threads). Pure.
add_executable(cdmp_tests_optd_weather_sync tests/optd_weather_sync_tests.cpp)
cdmp_strict(cdmp_tests_optd_weather_sync)
target_link_libraries(cdmp_tests_optd_weather_sync PRIVATE cdmp_common)
add_test(NAME optd_weather_sync COMMAND cdmp_tests_optd_weather_sync)
# P8 session 25 grabs (catch_seq_logic.h): the decision at ClientCatch_ApplyResult's entry, the counters and the
# self-consistency of the verified build-2976 bytes. Pure.
add_executable(cdmp_tests_optd_catch_seq tests/optd_catch_seq_tests.cpp)
cdmp_strict(cdmp_tests_optd_catch_seq)
target_link_libraries(cdmp_tests_optd_catch_seq PRIVATE cdmp_common)
add_test(NAME optd_catch_seq COMMAND cdmp_tests_optd_catch_seq)
# P8 session 25 rope (remote_rope_logic.h): the decisions at RemoteCatchComponent_Apply's entry and after the server's
# release, the 2471 payload, the transform math and the self-consistency of the verified build-2976 bytes. Pure.
add_executable(cdmp_tests_optd_remote_rope tests/optd_remote_rope_tests.cpp)
cdmp_strict(cdmp_tests_optd_remote_rope)
target_link_libraries(cdmp_tests_optd_remote_rope PRIVATE cdmp_common)
target_compile_definitions(cdmp_tests_optd_remote_rope PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd_remote_rope COMMAND cdmp_tests_optd_remote_rope)
# P8 session 27 rope probes (rope_probe_logic.h): the device packets' parsing, the per-character counters and the
# self-consistency of the verified build-2976 bytes. Pure.
add_executable(cdmp_tests_optd_rope_probe tests/optd_rope_probe_tests.cpp)
cdmp_strict(cdmp_tests_optd_rope_probe)
target_link_libraries(cdmp_tests_optd_rope_probe PRIVATE cdmp_common)
add_test(NAME optd_rope_probe COMMAND cdmp_tests_optd_rope_probe)
# P8 session 29 tree bend (tree_bend_logic.h): the state-15 frame, the sender's rate limits, the receiver's seq / age /
# connection handling and interpolation, the observer's decision and the verified build-2976 bytes.
add_executable(cdmp_tests_optd_tree_bend tests/optd_tree_bend_tests.cpp)
cdmp_strict(cdmp_tests_optd_tree_bend)
target_link_libraries(cdmp_tests_optd_tree_bend PRIVATE cdmp_common)
add_test(NAME optd_tree_bend COMMAND cdmp_tests_optd_tree_bend)
# P8 session 28 docked gimmicks (docked_gimmicks_logic.h): the 2005 classification and rewrite on S27's real
# records, the withheld requests, the probe tables and the self-consistency of the verified build-2976 bytes. Pure.
add_executable(cdmp_tests_optd_docked_gimmicks tests/optd_docked_gimmicks_tests.cpp)
cdmp_strict(cdmp_tests_optd_docked_gimmicks)
target_link_libraries(cdmp_tests_optd_docked_gimmicks PRIVATE cdmp_common)
add_test(NAME optd_docked_gimmicks COMMAND cdmp_tests_optd_docked_gimmicks)
# P8 session 28 gimmick projectiles (gimmick_event_dedup_logic.h): the guest's 2779 decision, the controllers from
# the 2005s and the host's duplicate classification, on S27's real bytes. Pure.
add_executable(cdmp_tests_optd_gimmick_event_dedup tests/optd_gimmick_event_dedup_tests.cpp)
cdmp_strict(cdmp_tests_optd_gimmick_event_dedup)
target_link_libraries(cdmp_tests_optd_gimmick_event_dedup PRIVATE cdmp_common)
add_test(NAME optd_gimmick_event_dedup COMMAND cdmp_tests_optd_gimmick_event_dedup)
# C4 (reconnect): the guest's epochs, the barrier and the read-only probes on fake game memory.
add_executable(cdmp_tests_optd_c4 tests/optd_c4_tests.cpp src/mod/session2/guest_lifecycle.cpp
    src/mod/game/safe_memory.cpp)
cdmp_strict(cdmp_tests_optd_c4)
target_link_libraries(cdmp_tests_optd_c4 PRIVATE cdmp_common)
add_test(NAME optd_c4 COMMAND cdmp_tests_optd_c4)
# P8 re-entry (docs/research/s25/reentrada.md): the control states 13/14, the host's answer, the guest's state machine
# and the per-conversation resets of the pure tables (pure).
add_executable(cdmp_tests_optd_rejoin tests/optd_rejoin_tests.cpp)
cdmp_strict(cdmp_tests_optd_rejoin)
target_link_libraries(cdmp_tests_optd_rejoin PRIVATE cdmp_common)
add_test(NAME optd_rejoin COMMAND cdmp_tests_optd_rejoin)
# C2-0: the identity probe's read chain and user-2 predicate on fake game memory.
add_executable(cdmp_tests_optd_identity tests/optd_identity_tests.cpp src/mod/session2/identity_probe.cpp
    src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_identity)
target_link_libraries(cdmp_tests_optd_identity PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_identity COMMAND cdmp_tests_optd_identity)
# C2: the identity fix's lobby edit, Status write, invariant and admission on fake game memory.
add_executable(cdmp_tests_optd_identity_fix tests/optd_identity_fix_tests.cpp src/mod/session2/identity_fix.cpp
    src/mod/session2/identity_probe.cpp src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_identity_fix)
target_link_libraries(cdmp_tests_optd_identity_fix PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_identity_fix COMMAND cdmp_tests_optd_identity_fix)
# Companions step A: the companion probe's key/owner predicates and control-component reads on fake game memory.
add_executable(cdmp_tests_optd_companion tests/optd_companion_tests.cpp src/mod/session2/companion_probe.cpp
    src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_companion)
target_link_libraries(cdmp_tests_optd_companion PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_companion COMMAND cdmp_tests_optd_companion)
# D-53: the child hold's predicate, split, table and release rules on fake game memory.
add_executable(cdmp_tests_optd_child_hold tests/optd_child_hold_tests.cpp src/mod/session2/child_hold.cpp
    src/mod/session2/observer_hold_acks.cpp
    src/mod/session2/guest_lifecycle.cpp src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_child_hold)
target_link_libraries(cdmp_tests_optd_child_hold PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_child_hold COMMAND cdmp_tests_optd_child_hold)
# S3: the host's observer hold (child_hold.cpp, NPC rules) and the guest's probe logic (guest_s3_logic.h: ring,
# key sets, update-guard table, 2005 parser on two payloads of the P8 session-4 capture in tests/data).
add_executable(cdmp_tests_optd_s3 tests/optd_s3_tests.cpp src/mod/session2/child_hold.cpp
    src/mod/session2/observer_hold_acks.cpp
    src/mod/session2/guest_lifecycle.cpp src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_s3)
target_link_libraries(cdmp_tests_optd_s3 PRIVATE cdmp_common safetyhook::safetyhook)
target_compile_definitions(cdmp_tests_optd_s3 PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd_s3 COMMAND cdmp_tests_optd_s3)
# P8 character_hold (child_hold.cpp, a user's main character with restore 0) and the holds' thread rule,
# through the same test seams; observer_hold_acks with a character.
add_executable(cdmp_tests_optd_character_hold tests/optd_character_hold_tests.cpp src/mod/session2/child_hold.cpp
    src/mod/session2/observer_hold_acks.cpp
    src/mod/session2/guest_lifecycle.cpp src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_character_hold)
target_link_libraries(cdmp_tests_optd_character_hold PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_character_hold COMMAND cdmp_tests_optd_character_hold)
# P8 title: the guest's slot refresh planner (pending/busy/retries) and the table description.
add_executable(cdmp_tests_optd_slot_refresh tests/optd_slot_refresh_tests.cpp src/mod/session2/slot_refresh.cpp)
cdmp_strict(cdmp_tests_optd_slot_refresh)
target_link_libraries(cdmp_tests_optd_slot_refresh PRIVATE cdmp_common)
add_test(NAME optd_slot_refresh COMMAND cdmp_tests_optd_slot_refresh)
# P8 session 25, the guest's own save, phase A (noche/progreso-invitado.md): the header check (also on the real
# template files when present), the slot rules, the LoadSlot / SavePlayerToSlot decisions per caller, the
# slot-file plan, the fail-closed rules and the mailbox generations. Not the hooks nor the game's behaviour.
add_executable(cdmp_tests_optd_guest_save tests/optd_guest_save_tests.cpp)
cdmp_strict(cdmp_tests_optd_guest_save)
target_link_libraries(cdmp_tests_optd_guest_save PRIVATE cdmp_common)
add_test(NAME optd_guest_save COMMAND cdmp_tests_optd_guest_save)
# P8 session 25, the guest's own save, phase B (guest_save_wire.h, sha256.h): SHA-256 (NIST vectors, BCrypt), the
# tunnel states 6-11, chunking and reassembly, the host's result bookkeeping, the guest's holds, the host's final save,
# the Req policy, the slot / account picks and the manifests. Not the hooks, the threads, the files or the game.
add_executable(cdmp_tests_optd_guest_save_b tests/optd_guest_save_b_tests.cpp)
cdmp_strict(cdmp_tests_optd_guest_save_b)
target_link_libraries(cdmp_tests_optd_guest_save_b PRIVATE cdmp_common bcrypt)
add_test(NAME optd_guest_save_b COMMAND cdmp_tests_optd_guest_save_b)
# P8 guest, the host's field actors: the remote predicate, the .rsrc-only section check, the log budgets,
# the lock-free key set, the loading state 0x12's wait-list replay and the ClientActorContainer::Find replay.
add_executable(cdmp_tests_optd_guest_actor tests/optd_guest_actor_tests.cpp)
cdmp_strict(cdmp_tests_optd_guest_actor)
target_link_libraries(cdmp_tests_optd_guest_actor PRIVATE cdmp_common)
add_test(NAME optd_guest_actor COMMAND cdmp_tests_optd_guest_actor)
# P8 S15 guest_reload_wait_fix (pendientes/p8-s15-viaje-tunel.md §8): offline logic only - the trip clock, the
# reload test, the snapshot, the drop decision with every refusal, 0x12's swap-remove replay on the S15 list and the
# age table. They do NOT test the hook, the lock or the game's behaviour.
add_executable(cdmp_tests_optd_reload_wait tests/optd_reload_wait_tests.cpp)
cdmp_strict(cdmp_tests_optd_reload_wait)
target_link_libraries(cdmp_tests_optd_reload_wait PRIVATE cdmp_common)
add_test(NAME optd_reload_wait COMMAND cdmp_tests_optd_reload_wait)
# P8 S1/S2 probes (pendientes/p8-impl-s1s2.md): offline logic only (no game) - the event ring, rate and per-key
# limits, change-only gate, the wait-list count with unreadable slots, ActionGraph_Find's replay, the restart path
# and the 0xA97D60 predicate attribution.
add_executable(cdmp_tests_optd_p8_probe tests/optd_p8_probe_tests.cpp)
cdmp_strict(cdmp_tests_optd_p8_probe)
target_link_libraries(cdmp_tests_optd_p8_probe PRIVATE cdmp_common)
add_test(NAME optd_p8_probe COMMAND cdmp_tests_optd_p8_probe)
# P8 S1+S2, user 2 as an observer of the field's stages (pendientes/p8-observador-escenas.md): offline logic only -
# the 2661/2810/2322 payload parsers on the host's captured packets, the live-sequencer ledger, what a non-owner
# entry lacks, the follow-up schedule and the refused send mode.
add_executable(cdmp_tests_optd_observer_stage tests/optd_observer_stage_tests.cpp)
cdmp_strict(cdmp_tests_optd_observer_stage)
target_link_libraries(cdmp_tests_optd_observer_stage PRIVATE cdmp_common)
add_test(NAME optd_observer_stage COMMAND cdmp_tests_optd_observer_stage)

# P8 phase 2 (pendientes/p8-observador-escenas.md Fase 2): offline logic only - the guest probe's 2661/2981 parsers
# on the captured packets, the corr= token both PCs print, the routing/result verdicts, the NPC-side tracker and the
# host ledger's invalidation and native order.
add_executable(cdmp_tests_optd_guest_stage tests/optd_guest_stage_tests.cpp)
cdmp_strict(cdmp_tests_optd_guest_stage)
target_link_libraries(cdmp_tests_optd_guest_stage PRIVATE cdmp_common)
add_test(NAME optd_guest_stage COMMAND cdmp_tests_optd_guest_stage)
# P8 S2, the native 2322 for an observer (pendientes/p8-2322-observador.md): offline logic only - the host's trip
# ledger and decision (order, duplicates, invalidation, reconnection, queue failure, wrong recipient, switch off) and
# the guest's loading-cycle tracker. They do NOT test the hooks, the ABI or the game's behaviour.
add_executable(cdmp_tests_optd_observer_milestone tests/optd_observer_milestone_tests.cpp)
cdmp_strict(cdmp_tests_optd_observer_milestone)
target_link_libraries(cdmp_tests_optd_observer_milestone PRIVATE cdmp_common)
add_test(NAME optd_observer_milestone COMMAND cdmp_tests_optd_observer_milestone)
# The guest's repeat of a 2322 its own login wrote back (preload_release_logic.h): offline logic only.
add_executable(cdmp_tests_optd_preload_release tests/optd_preload_release_tests.cpp)
cdmp_strict(cdmp_tests_optd_preload_release)
target_include_directories(cdmp_tests_optd_preload_release PRIVATE src)
add_test(NAME optd_preload_release COMMAND cdmp_tests_optd_preload_release)
# Which hide requests are refused so the two players can see each other (remote_visible_logic.h): offline logic only.
add_executable(cdmp_tests_optd_remote_visible tests/optd_remote_visible_tests.cpp)
cdmp_strict(cdmp_tests_optd_remote_visible)
target_include_directories(cdmp_tests_optd_remote_visible PRIVATE src)
add_test(NAME optd_remote_visible COMMAND cdmp_tests_optd_remote_visible)
add_executable(cdmp_tests_optd_milestone_native tests/optd_milestone_native_tests.cpp)
cdmp_strict(cdmp_tests_optd_milestone_native)
target_include_directories(cdmp_tests_optd_milestone_native PRIVATE src)
add_test(NAME optd_milestone_native COMMAND cdmp_tests_optd_milestone_native
    --exe "${CMAKE_CURRENT_SOURCE_DIR}/../bin64/CrimsonDesert.exe")
set_tests_properties(optd_milestone_native PROPERTIES SKIP_RETURN_CODE 77)
add_executable(cdmp_tests_optd_apply_playback tests/optd_apply_playback_tests.cpp)
cdmp_strict(cdmp_tests_optd_apply_playback)
target_include_directories(cdmp_tests_optd_apply_playback PRIVATE src)
target_link_libraries(cdmp_tests_optd_apply_playback PRIVATE safetyhook::safetyhook)
add_test(NAME optd_apply_playback COMMAND cdmp_tests_optd_apply_playback
    --exe "${CMAKE_CURRENT_SOURCE_DIR}/../bin64/CrimsonDesert.exe")
set_tests_properties(optd_apply_playback PROPERTIES SKIP_RETURN_CODE 77)
# P2 without game heap work on the mod's threads (pendientes/p8-heap-inyeccion.md): offline logic only - the
# classification (hold/drop/stop), the queue to the NetworkThread (order, bounds, reserve, epochs), the in-flight
# bound, the 2001's pacing, the stall watch, the exception notes and a simulated host pause.
add_executable(cdmp_tests_optd_inject tests/optd_inject_tests.cpp)
cdmp_strict(cdmp_tests_optd_inject)
target_link_libraries(cdmp_tests_optd_inject PRIVATE cdmp_common)
add_test(NAME optd_inject COMMAND cdmp_tests_optd_inject)
# P8 scenes of user 2 and the observer_hold side effect (pendientes/p8-escenas-y-acks.md): offline logic only - the
# book of user 2's 2661/2810 and the copy decision (observer_scene_copy_logic.h) on the session-6B packets, and the
# hold of a withheld NPC's per-actor packets until its 2005 (observer_hold_acks_logic.h): order, bounds, drops,
# orphans, epochs, the 2005 key parser on the session-4 fixtures. Not the hooks, the ABI or the game.
add_executable(cdmp_tests_optd_scene_acks tests/optd_scene_acks_tests.cpp)
cdmp_strict(cdmp_tests_optd_scene_acks)
target_link_libraries(cdmp_tests_optd_scene_acks PRIVATE cdmp_common)
target_compile_definitions(cdmp_tests_optd_scene_acks PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd_scene_acks COMMAND cdmp_tests_optd_scene_acks)
# P8 S1 option A, sequencers (docs/research/pendientes/p8-impl-opcion-a.md): the host's ledger, user 2's trips,
# the order after the 2005 of every bound actor, the gate, the C>S filter (observer_seq_copy_logic.h) and the guest's
# routing decision and delivery gate (guest_seq_route_logic.h), on packets of the session 7 captures; and the
# schedule-stage snapshot / live copies (observer_sched_copy, docs/research/pendientes/p8-impl-horarios-snapshot.md).
add_executable(cdmp_tests_optd_seq_copy tests/optd_seq_copy_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_copy)
target_link_libraries(cdmp_tests_optd_seq_copy PRIVATE cdmp_common)
add_test(NAME optd_seq_copy COMMAND cdmp_tests_optd_seq_copy)
# P8 guest_seq_play (docs/research/pendientes/p8-impl-escenas-play.md): the per-frame plan for the host character's
# manager X (identity checks, frame conditions, the 2 -> 3 step once per routed 2322, live), the table of X the
# routing hooks fill (also from several threads), the G5 state types. Not the hook, the calls or the game.
add_executable(cdmp_tests_optd_seq_play tests/optd_seq_play_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_play)
target_link_libraries(cdmp_tests_optd_seq_play PRIVATE cdmp_common)
add_test(NAME optd_seq_play COMMAND cdmp_tests_optd_seq_play)
# P8 session 9, guest_x_veto (docs/research/pendientes/p8-s9-cinematica.md §8): offline logic only - the keys, whose
# stage manager runs a stage chart function (own M, another character's X, unknown owner...), what each mode does, the
# X context's stack rule, the camera key, and B1 (a save loaded locally after a remote session).
add_executable(cdmp_tests_optd_x_veto tests/optd_x_veto_tests.cpp)
cdmp_strict(cdmp_tests_optd_x_veto)
target_link_libraries(cdmp_tests_optd_x_veto PRIVATE cdmp_common)
add_test(NAME optd_x_veto COMMAND cdmp_tests_optd_x_veto)
# P8 mounts, mount_sync (docs/research/pendientes/p8-impl-monturas.md): offline logic only - the tunnel event's wire
# format, the observer's transactions (hold, commit, detach, timeouts, idempotency, quarantine, nonce), the
# pre-apply judgement, the postconditions and the dispatch fallback.
add_executable(cdmp_tests_optd_mount_sync tests/optd_mount_sync_tests.cpp)
cdmp_strict(cdmp_tests_optd_mount_sync)
target_link_libraries(cdmp_tests_optd_mount_sync PRIVATE cdmp_common)
add_test(NAME optd_mount_sync COMMAND cdmp_tests_optd_mount_sync)
# P8 session 13, the shopkeepers (docs/research/pendientes/p8-impl-tenderos-c1.md): offline logic only - the read-only
# replica of 0x1F6C190 (id hash = lookup3 initval 0xC5EDE, bucket walk, dead flag) on a fake table, the C1 decision and
# its modes, the X slots and checks, the per-id book, and the shop probe's per-character table, names and packets.
add_executable(cdmp_tests_optd_shop_c1 tests/optd_shop_c1_tests.cpp)
cdmp_strict(cdmp_tests_optd_shop_c1)
target_link_libraries(cdmp_tests_optd_shop_c1 PRIVATE cdmp_common)
add_test(NAME optd_shop_c1 COMMAND cdmp_tests_optd_shop_c1)
# P8 option U, U-0 (research/s25/mundo-escenarios-propios.md): offline logic only - the key, the cells and world
# positions as 0x288B7A0 / 0x4F8220 compute them, the arm check, the would-be state machine, who, the timer table, the
# (reason, caller) table and the overlap counts. Not the hooks or the game.
add_executable(cdmp_tests_optd_user2_stages tests/optd_user2_stages_tests.cpp)
cdmp_strict(cdmp_tests_optd_user2_stages)
target_link_libraries(cdmp_tests_optd_user2_stages PRIVATE cdmp_common)
add_test(NAME optd_user2_stages COMMAND cdmp_tests_optd_user2_stages)
# S37 phase D (docs/research/s25/s37-fase-d.md): user2_fast_rearm's pure logic (fast_rearm_logic.h): the fast verdict,
# the one-shot 2043 (payload, delay unit, one pending per arm, cancel / lost / late) and the leftover WRN verdict.
add_executable(cdmp_tests_optd_fast_rearm tests/optd_fast_rearm_tests.cpp)
cdmp_strict(cdmp_tests_optd_fast_rearm)
target_link_libraries(cdmp_tests_optd_fast_rearm PRIVATE cdmp_common)
add_test(NAME optd_fast_rearm COMMAND cdmp_tests_optd_fast_rearm)
# P8 option U, U2 (research/s25/tiendas-u2.md): the shop route's pure logic (user2_shops_logic.h).
add_executable(cdmp_tests_optd_user2_shops tests/optd_user2_shops_tests.cpp)
cdmp_strict(cdmp_tests_optd_user2_shops)
target_link_libraries(cdmp_tests_optd_user2_shops PRIVATE cdmp_common)
add_test(NAME optd_user2_shops COMMAND cdmp_tests_optd_user2_shops)
# S46 phase 1 (docs/research/s25/s46-tenderos.md): the pure headers ported by hand from opcion-d-tenderos (shop_troc,
# the 3000 layout, the trade list with its hashes).
add_executable(cdmp_tests_optd_shop_troc tests/optd_shop_troc_tests.cpp)
cdmp_strict(cdmp_tests_optd_shop_troc)
target_link_libraries(cdmp_tests_optd_shop_troc PRIVATE cdmp_common)
add_test(NAME optd_shop_troc COMMAND cdmp_tests_optd_shop_troc)
# S46 phase 1: shop_trade_probe's pure logic (R0, U2-c, P1, the ledger, the eErrNo table).
add_executable(cdmp_tests_optd_shop_trade tests/optd_shop_trade_tests.cpp)
cdmp_strict(cdmp_tests_optd_shop_trade)
target_link_libraries(cdmp_tests_optd_shop_trade PRIVATE cdmp_common)
add_test(NAME optd_shop_trade COMMAND cdmp_tests_optd_shop_trade)
# S46 phase 1, T2 probe: observer_hold_scene_order's pure logic (hold_scene_order_logic.h).
add_executable(cdmp_tests_optd_hold_scene_order tests/optd_hold_scene_order_tests.cpp)
cdmp_strict(cdmp_tests_optd_hold_scene_order)
target_link_libraries(cdmp_tests_optd_hold_scene_order PRIVATE cdmp_common)
add_test(NAME optd_hold_scene_order COMMAND cdmp_tests_optd_hold_scene_order)
# P8 guest_schedule_load (docs/research/pendientes/p8-impl-horarios.md): offline logic only - the key's values, the
# name -> key hash (lookup3, initval 0xC5EDE) and 0x1422F90's base name, the schedule-context table replica and the
# name read on fake memory, the key set, the keys a 2005 / 2335 / 2874 names (session-6 records), the per-key book
# (also from several threads), the budget and the decision order. Not the hooks, the loader call or the game.
add_executable(cdmp_tests_optd_sched_load tests/optd_sched_load_tests.cpp)
cdmp_strict(cdmp_tests_optd_sched_load)
target_link_libraries(cdmp_tests_optd_sched_load PRIVATE cdmp_common)
target_compile_definitions(cdmp_tests_optd_sched_load PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd_sched_load COMMAND cdmp_tests_optd_sched_load)
# P8 strategy B step 2 (docs/research/pendientes/p8-impl-owner-fanout.md): the owner fan-out probe's mode, the
# generated writer table (return of finder->vf1 -> writer -> opcode), the families of §3.4, the observer-trip rule,
# the verdict of one ToTarget::vf1 call, the lock-free counters, the top list and the comparison. Not the hook.
add_executable(cdmp_tests_optd_owner_fanout tests/optd_owner_fanout_tests.cpp)
cdmp_strict(cdmp_tests_optd_owner_fanout)
target_link_libraries(cdmp_tests_optd_owner_fanout PRIVATE cdmp_common)
add_test(NAME optd_owner_fanout COMMAND cdmp_tests_optd_owner_fanout)
# P8 seq_actor_restore (docs/research/pendientes/p8-impl-seq-restore.md): the replica of ActionGraph_Find 0x24314C0
# on fake charts, every verdict of the decision (fast path, remote, resolvable, other failure, unreadable, wait,
# drop, skip, exit registers, probe) on the session-8 cases, and the touched-key log. Not the hook or the game.
add_executable(cdmp_tests_optd_seq_restore tests/optd_seq_restore_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_restore)
target_link_libraries(cdmp_tests_optd_seq_restore PRIVATE cdmp_common)
add_test(NAME optd_seq_restore COMMAND cdmp_tests_optd_seq_restore)
# P8 session 13 (docs/research/pendientes/p8-impl-secuenciador-bodyanim.md): offline logic only - guest_seq_route_2524's
# modes (legacy / probe / 1 and the point), the world classification of a 2524's scene (class by class, the session 12
# scenes), the function-scene names, the name decoding, the routing verdict with the world check, the 2661 binds
# ledger; guest_seq_bodyanim_diag's configure caller, body states and cohort. Not the hooks or the game.
add_executable(cdmp_tests_optd_seq_bodyanim tests/optd_seq_bodyanim_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_bodyanim)
target_link_libraries(cdmp_tests_optd_seq_bodyanim PRIVATE cdmp_common)
add_test(NAME optd_seq_bodyanim COMMAND cdmp_tests_optd_seq_bodyanim)
# P8 guest, the host's packets into the client only from its NetworkThread (pendientes/p8-auditoria-hilos.md):
# offline logic only - the queue (order, bounds, per-turn cap, clear), the delivery measures, the thread-owner
# check, a simulated zone load and a stall of the NetworkThread. Not the hooks, the ABI or the game's threads.
add_executable(cdmp_tests_optd_guest_inbound tests/optd_guest_inbound_tests.cpp)
cdmp_strict(cdmp_tests_optd_guest_inbound)
target_link_libraries(cdmp_tests_optd_guest_inbound PRIVATE cdmp_common)
add_test(NAME optd_guest_inbound COMMAND cdmp_tests_optd_guest_inbound)
# P8, menus without the pause while another player is connected (pendientes/p8-pausa-esc.md): offline logic only -
# the ui_pause_block modes, the decision table (pause / UI slowdown blocked, 1 / >1 / garbage passed, gameplay slow
# motion untouched in a model of 0xAD1300), the session-live gating, the replay of 0x35CD990's view walk on fake
# memory, the ring event packing and the per-UI ledger. Not the hook, the ABI or the game's behaviour.
add_executable(cdmp_tests_optd_ui_pause tests/optd_ui_pause_tests.cpp)
cdmp_strict(cdmp_tests_optd_ui_pause)
target_link_libraries(cdmp_tests_optd_ui_pause PRIVATE cdmp_common)
add_test(NAME optd_ui_pause COMMAND cdmp_tests_optd_ui_pause)
# P8 gameplay for user 2 (pendientes/p8-impl-rango-embudos.md): offline logic only - the three modes, the rank
# permit decision for user 2's character, the subject verdict at ExecuteTroc, the funnel decision (shared field, own
# field, other caller, keys), the quest-manager chain on fake memory and the lock-free counters. Not the hooks, the
# call-site patch, the ABI or the game's behaviour.
add_executable(cdmp_tests_optd_user2_funnels tests/optd_user2_funnels_tests.cpp)
cdmp_strict(cdmp_tests_optd_user2_funnels)
target_link_libraries(cdmp_tests_optd_user2_funnels PRIVATE cdmp_common)
add_test(NAME optd_user2_funnels COMMAND cdmp_tests_optd_user2_funnels)

# The world around user 2 (docs/research/noche/mundo-invitado.md, "Implementado"): offline logic only -
# world_anchor_logic.h's state machine (set after a 2762 in a field the host owns, the leaves 2437/2283/2001 and the
# re-arm, the watchdog's verify / lost / busy / field reset, the fallback clear when user 2 is gone, epochs, probe's
# "would" path) and the probe's 2516 reader and removal statistics. Not the hook, the lock call or the game.
add_executable(cdmp_tests_optd_world_anchor tests/optd_world_anchor_tests.cpp)
cdmp_strict(cdmp_tests_optd_world_anchor)
target_link_libraries(cdmp_tests_optd_world_anchor PRIVATE cdmp_common)
add_test(NAME optd_world_anchor COMMAND cdmp_tests_optd_world_anchor)

add_executable(cdmp_tests_optd_fast_travel tests/optd_fast_travel_tests.cpp)
cdmp_strict(cdmp_tests_optd_fast_travel)
target_link_libraries(cdmp_tests_optd_fast_travel PRIVATE cdmp_common)
add_test(NAME optd_fast_travel COMMAND cdmp_tests_optd_fast_travel)
# P8, the other player's character as a native remote actor (pendientes/p8-impl-escalada.md): offline logic only -
# the remote_climb modes, the PointClimb::Enter decision (forced only in control mode 2 for a 0xA01 key, never in
# mode 1/3), the wall-up byte's section and page checks and its watch, the probe's triggers, ring, episode window and
# segment log. Not the hook, the ABI, the byte write or the game's behaviour.
add_executable(cdmp_tests_optd_remote_motion tests/optd_remote_motion_tests.cpp)
cdmp_strict(cdmp_tests_optd_remote_motion)
target_link_libraries(cdmp_tests_optd_remote_motion PRIVATE cdmp_common)
add_test(NAME optd_remote_motion COMMAND cdmp_tests_optd_remote_motion)
# P8 remote movement (pendientes/p8-impl-interp-remota.md): offline logic only - remote_interp_logic.h (the target
# and its approach, the insert observation, the lock-free per-controller table with concurrent threads, the
# buffer->actor chain and the last sample on fake memory, the decision) and horse_follow_logic.h (the Move shapes, the
# horse's synthetic 2697 byte by byte, the verdicts, the key ring and cadences). Not the hooks, the patch, the ABI.
add_executable(cdmp_tests_optd_remote_interp tests/optd_remote_interp_tests.cpp)
cdmp_strict(cdmp_tests_optd_remote_interp)
target_link_libraries(cdmp_tests_optd_remote_interp PRIVATE cdmp_common)
add_test(NAME optd_remote_interp COMMAND cdmp_tests_optd_remote_interp)
add_executable(cdmp_tests_native_movement tests/native_movement_tests.cpp)
cdmp_strict(cdmp_tests_native_movement)
target_link_libraries(cdmp_tests_native_movement PRIVATE cdmp_common)
add_test(NAME native_movement COMMAND cdmp_tests_native_movement)
# P8 session 8 pets (pendientes/p8-impl-mascotas.md): child_settle through child_hold.cpp's test seams (the split
# with the owner's character in the same call / just announced / still withheld, the timed native re-announce,
# drops, D-53's wait, observer_hold_acks), its pure rules (child_settle_logic.h), remote_interp's cap for owned
# actors and gaps while attached (remote_interp_logic.h), and attach_follow_logic.h (the StartAction layout, the
# quaternion maths, the tracker, the synthetic 2697/2556 byte by byte, the registry).
add_executable(cdmp_tests_optd_pets tests/optd_pets_tests.cpp src/mod/session2/child_hold.cpp
    src/mod/session2/observer_hold_acks.cpp
    src/mod/session2/guest_lifecycle.cpp src/mod/game/safe_memory.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_pets)
target_link_libraries(cdmp_tests_optd_pets PRIVATE cdmp_common safetyhook::safetyhook)
add_test(NAME optd_pets COMMAND cdmp_tests_optd_pets)
# P8 session 9 (pendientes/p8-impl-s9-movimiento.md): offline logic only - ride_filter_logic.h (the StartActionAck
# layout and the in-place rewrite on real packets of the session 9 host capture), reannounce_logic.h and
# child_settle's re-announce wait, combat_follow_logic.h (engagement, table, decisions, ts, the synthetic 2697 byte
# for byte against a real enemy Ack) and horse_follow_logic.h's synthetic 2556 (never sent). Not the hooks.
add_executable(cdmp_tests_optd_s9 tests/optd_s9_tests.cpp)
cdmp_strict(cdmp_tests_optd_s9)
target_link_libraries(cdmp_tests_optd_s9 PRIVATE cdmp_common)
add_test(NAME optd_s9 COMMAND cdmp_tests_optd_s9)
# P8 session 25, the combat stream (docs/research/noche/combate-retardo.md §6): offline logic only -
# combat_follow_logic.h's v2 (fights with any character, the game's thresholds, the same-pose keepalive, no stale cut,
# the shadow stream, the drift-free schedule, the nearest first) and remote_interp_logic.h's combat class (arrivals,
# dense / engaged, target, descent, probe's shadow, exclusions, the engagement table), on the session 10 guest's enemy
# 0xB0101EF7 and a synthetic 33 ms stream. Not the hooks, the threads, the timer.
add_executable(cdmp_tests_optd_combat tests/optd_combat_tests.cpp)
cdmp_strict(cdmp_tests_optd_combat)
target_link_libraries(cdmp_tests_optd_combat PRIVATE cdmp_common)
add_test(NAME optd_combat COMMAND cdmp_tests_optd_combat)
# P8 S1, NPC scenes, the measurement probes (pendientes/p8-s1-escenas-npc.md "Implementado para la medida"):
# offline logic only - the 2335/2661/2874/2126/2411/2005/2223 and C>S scene Req parsers on records of the session-6
# captures (tests/data/p8s6_*.bin, hex below), the AI block search, the NPCScheduleManager lookup replica on a fake
# memory, the lock-free count table and its limits, the scene ledger, the trip tracker and the NPC timeline.
add_executable(cdmp_tests_optd_scene_diag tests/optd_scene_diag_tests.cpp)
cdmp_strict(cdmp_tests_optd_scene_diag)
target_link_libraries(cdmp_tests_optd_scene_diag PRIVATE cdmp_common)
target_compile_definitions(cdmp_tests_optd_scene_diag PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd_scene_diag COMMAND cdmp_tests_optd_scene_diag)
# P8 session 8, the asynchronous logger (pendientes/p8-impl-log-async.md): the ring's logic offline (order, wrap,
# bounds, drop and count with the "dropped here" note, cut lines, raw records, the exit drain), a writer blocked 1 s
# that does not hold concurrent producers, and log.cpp on a file in %TEMP% (rotation, order, flush, emergency, close).
# P8 session 10, freeze_watchdog (pendientes/p8-impl-freeze-watchdog.md): the episode machine (stall, sample cadence,
# caps, END), the "call right before" test of return addresses, the per-thread hook marks, and the stack sample
# (freeze_sample.h) on a real thread of the test. Not the hooks or the game.
add_executable(cdmp_tests_optd_freeze_watchdog tests/optd_freeze_watchdog_tests.cpp)
cdmp_strict(cdmp_tests_optd_freeze_watchdog)
target_include_directories(cdmp_tests_optd_freeze_watchdog PRIVATE src)
add_test(NAME optd_freeze_watchdog COMMAND cdmp_tests_optd_freeze_watchdog)
add_executable(cdmp_tests_optd_log_ring tests/optd_log_ring_tests.cpp src/mod/log.cpp)
cdmp_strict(cdmp_tests_optd_log_ring)
target_include_directories(cdmp_tests_optd_log_ring PRIVATE src)
add_test(NAME optd_log_ring COMMAND cdmp_tests_optd_log_ring)
set_tests_properties(optd_log_ring PROPERTIES TIMEOUT 120)
# cdmp_peer --mode replay against a fake host over loopback UDP (port 37115).
add_executable(cdmp_tests_optd_replay tests/optd_replay_tests.cpp tools/peer_sim/replay.cpp tools/peer_sim/save_sim.cpp)
cdmp_strict(cdmp_tests_optd_replay)
target_link_libraries(cdmp_tests_optd_replay PRIVATE cdmp_common)
add_test(NAME optd_replay COMMAND cdmp_tests_optd_replay)
# The login scripts (docs/research/data/*.troc) match make_troc_script.py and their JSON.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME optd_scripts COMMAND Python3::Interpreter -I -B ${CMAKE_SOURCE_DIR}/tools/scripts/check_troc_scripts.py)
endif()

# S33: pruebas puras de activación, presupuesto por nodo y sondas del cliente.
add_executable(cdmp_tests_optd_npc_activation tests/optd_npc_activation_tests.cpp)
cdmp_strict(cdmp_tests_optd_npc_activation)
target_link_libraries(cdmp_tests_optd_npc_activation PRIVATE cdmp_common)
add_test(NAME optd_npc_activation COMMAND cdmp_tests_optd_npc_activation)
add_executable(cdmp_tests_optd_npc_probe_client tests/optd_npc_probe_client_tests.cpp)
cdmp_strict(cdmp_tests_optd_npc_probe_client)
target_link_libraries(cdmp_tests_optd_npc_probe_client PRIVATE cdmp_common)
add_test(NAME optd_npc_probe_client COMMAND cdmp_tests_optd_npc_probe_client)
# S35 fase A (docs/research/s25/s35-fase-a.md): the pure admission rule of publication_gate (three CC states,
# dependencies, bounded retention). Its end-to-end exits run in optd_s3 (child_hold.cpp's seams).
add_executable(cdmp_tests_optd_publication_gate tests/optd_publication_gate_tests.cpp)
cdmp_strict(cdmp_tests_optd_publication_gate)
target_link_libraries(cdmp_tests_optd_publication_gate PRIVATE cdmp_common)
add_test(NAME optd_publication_gate COMMAND cdmp_tests_optd_publication_gate)
# S36 fase B (docs/research/s25/s36-fase-b.md): npc_family_control's pure logic (npc_family_logic.h): subtree scan on
# a synthetic arena, whole-unit reservation (63+2), nested Troc frames, parent birth, leaf-to-root exits, partial
# retirement, member matrix, census, probe changes nothing. Reads the audit's counterexamples file as fixture.
add_executable(cdmp_tests_optd_npc_family tests/optd_npc_family_tests.cpp)
cdmp_strict(cdmp_tests_optd_npc_family)
target_link_libraries(cdmp_tests_optd_npc_family PRIVATE cdmp_common)
target_compile_definitions(cdmp_tests_optd_npc_family PRIVATE CDMP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME optd_npc_family COMMAND cdmp_tests_optd_npc_family)
# S42: familias de horario con vehículos, sin juego ni memoria real.
add_executable(cdmp_tests_optd_npc_family_vehicles tests/optd_npc_family_vehicles_tests.cpp)
cdmp_strict(cdmp_tests_optd_npc_family_vehicles)
target_link_libraries(cdmp_tests_optd_npc_family_vehicles PRIVATE cdmp_common)
add_test(NAME optd_npc_family_vehicles COMMAND cdmp_tests_optd_npc_family_vehicles)
add_executable(cdmp_tests_optd_enemy_damage_probe tests/optd_enemy_damage_probe_tests.cpp)
cdmp_strict(cdmp_tests_optd_enemy_damage_probe)
target_link_libraries(cdmp_tests_optd_enemy_damage_probe PRIVATE cdmp_common)
add_test(NAME optd_enemy_damage_probe COMMAND cdmp_tests_optd_enemy_damage_probe)
add_executable(cdmp_tests_optd_door_trace tests/optd_door_trace_tests.cpp)
cdmp_strict(cdmp_tests_optd_door_trace)
target_link_libraries(cdmp_tests_optd_door_trace PRIVATE cdmp_common)
add_test(NAME optd_door_trace COMMAND cdmp_tests_optd_door_trace)
# S43 (docs/research/s25/s43-puertas-y-r42.md): scene_level_share's pure logic (scene_level_share_logic.h): the
# per-user loaded sets, the keep/delete decision, the owner gate, the 2598 / 2834 / 2104 parsers on captured bytes.
add_executable(cdmp_tests_optd_hud_status tests/optd_hud_status_tests.cpp)
cdmp_strict(cdmp_tests_optd_hud_status)
target_include_directories(cdmp_tests_optd_hud_status PRIVATE src)
add_test(NAME optd_hud_status COMMAND cdmp_tests_optd_hud_status)
add_executable(cdmp_tests_optd_scene_level_share tests/optd_scene_level_share_tests.cpp)
cdmp_strict(cdmp_tests_optd_scene_level_share)
target_link_libraries(cdmp_tests_optd_scene_level_share PRIVATE cdmp_common)
add_test(NAME optd_scene_level_share COMMAND cdmp_tests_optd_scene_level_share)
# S44 (docs/research/s25/s44-escenas-del-anfitrion.md): guest_seq_foreign's pure logic (guest_seq_foreign_logic.h): the
# 2661 and the handler's binding vector on captured bytes (rematch, shop, weather, item use, the guest's own), the
# per-binding decision (only the owner, only another player, never an NPC nor this client's own), modes 0 / probe / 1,
# limits, and the probes' classifications (P1 / P2's 0x205DC30 replica / P3).
add_executable(cdmp_tests_optd_seq_foreign tests/optd_seq_foreign_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_foreign)
target_link_libraries(cdmp_tests_optd_seq_foreign PRIVATE cdmp_common)
add_test(NAME optd_seq_foreign COMMAND cdmp_tests_optd_seq_foreign)
# S45 (docs/research/s25/s45-escenas-ajenas.md): guest_seq_present's pure logic (guest_seq_present_logic.h): whose a
# stage is, the processor vtable's class, R-A's table from three vtables, the stage table (P1 -> timeline id / sequencer),
# the timeline root walk, the event's verdict, S-D's change detection and the cost counter.
add_executable(cdmp_tests_optd_seq_present tests/optd_seq_present_tests.cpp)
cdmp_strict(cdmp_tests_optd_seq_present)
target_link_libraries(cdmp_tests_optd_seq_present PRIVATE cdmp_common)
add_test(NAME optd_seq_present COMMAND cdmp_tests_optd_seq_present)
# S38 fase C (docs/research/s25/s38-fase-c.md): user2_road_control's pure logic (user2_road_logic.h): provenance,
# whole caravans, registration before authority, strict leaf-to-root retirement and its continuation, stop rules.
add_executable(cdmp_tests_optd_user2_road tests/optd_user2_road_tests.cpp)
cdmp_strict(cdmp_tests_optd_user2_road)
target_link_libraries(cdmp_tests_optd_user2_road PRIVATE cdmp_common)
add_test(NAME optd_user2_road COMMAND cdmp_tests_optd_user2_road)
