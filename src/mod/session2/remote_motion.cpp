#include "mod/game/build_profile.h"
#include "mod/session2/remote_motion.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/remote_motion_logic.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using rmo::ClimbOut;
using rmo::Mode;

// ---------------------------------------------------------------- the sites (build 2976)
//
// Read with capstone from CrimsonDesert.exe 1.0.0.2976 (PE 0x6AB28F00) on disk
// (docs/research/pendientes/p8-impl-escalada.md §2). Every array is compared
// with the running game before anything is written; a difference leaves that
// piece off with an error line.

// PointClimbMovementMethod::Enter (vf7 of exe+0x5597028), .rsrc. Prologue:
//   4C 8B DC              mov r11,rsp
//   49 89 5B 10           mov [r11+0x10],rbx
//   49 89 6B 18           mov [r11+0x18],rbp
//   49 89 73 20           mov [r11+0x20],rsi
//   57                    push rdi
//   48 81 EC 80 00 00 00  sub rsp,0x80
// No RIP-relative operand; rcx = the method, dl = "same method" (al = result).
uintptr_t kPointClimbEnter = 0x691400;
constexpr uint8_t kPointClimbHead[] = {0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x10, 0x49, 0x89, 0x6B, 0x18, 0x49,
                                       0x89, 0x73, 0x20, 0x57, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00};
constexpr uint32_t kPointClimbBoundaries[] = {7, 11, 15, 16, 23};

// The control mode of a movement controller, 0x88E8E0(mc) -> al: 1 local
// (0x17F2A50), 3 when bit 2 of [[[mc+0x60]+0x60]+0x10], 2 when the actor
// [mc+0x68] has an owning user (+0x90 != 0), else further checks. Only reads.
// Its whole body 0x88E8E0..0x88E9B4, its jump table 0x88E9B4 (7 x u32 RVA),
// its callee 0x17F2A50..0x17F2A9A and that one's table 0x17F2A9C.
uintptr_t kModeFn = 0x88E8E0;
constexpr uint8_t kModeFnBytes[] = {
    0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0x51, 0x68, 0x4C, 0x8B, 0xD9, 0x49, 0x8B, 0xCA, 0xE8, 0x5D, 0x41, 0xF6,
    0x00, 0x84, 0xC0, 0x0F, 0x85, 0xB2, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x43, 0x60, 0x48, 0x8B, 0x48, 0x60, 0xF6,
    0x41, 0x10, 0x02, 0x0F, 0x85, 0x99, 0x00, 0x00, 0x00, 0x41, 0x83, 0xBA, 0x90, 0x00, 0x00, 0x00, 0x00, 0x0F,
    0x85, 0x84, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x50, 0x01, 0x80, 0xFA,
    0x01, 0x75, 0x19, 0x48, 0x8B, 0x05, 0x86, 0xA8, 0x4D, 0x06, 0x48, 0x8B, 0x48, 0x38, 0x48, 0x8B, 0x41, 0x50,
    0x48, 0x85, 0xC0, 0x74, 0x60, 0x49, 0x3B, 0xC2, 0x75, 0x5B, 0x4D, 0x8B, 0x4A, 0x68, 0x4D, 0x8B, 0x41, 0x48,
    0x4D, 0x85, 0xC0, 0x74, 0x55, 0x41, 0x80, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x00, 0x74, 0x4B, 0x8B, 0xC2, 0x83,
    0xC0, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x15, 0x94, 0x16, 0x77, 0xFF, 0x48, 0x98, 0x41, 0x8B,
    0x8C, 0x82, 0xB4, 0xE9, 0x88, 0x00, 0x49, 0x03, 0xCA, 0xFF, 0xE1, 0x80, 0xFA, 0x01, 0x75, 0x26, 0x49, 0x8B,
    0x41, 0x40, 0x80, 0xB8, 0xE9, 0x01, 0x00, 0x00, 0x00, 0x75, 0x20, 0x41, 0x80, 0xB8, 0xC8, 0x00, 0x00, 0x00,
    0x00, 0x0F, 0x9E, 0xC0, 0x04, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3,
    0xB0, 0x03, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x01, 0x48, 0x83, 0xC4, 0x28, 0xC3};
uintptr_t kModeFnTable = 0x88E9B4;
constexpr uint8_t kModeFnTableBytes[] = {0x80, 0xE9, 0x88, 0x00, 0x80, 0xE9, 0x88, 0x00, 0x80, 0xE9,
                                         0x88, 0x00, 0x80, 0xE9, 0x88, 0x00, 0x7B, 0xE9, 0x88, 0x00,
                                         0x80, 0xE9, 0x88, 0x00, 0x80, 0xE9, 0x88, 0x00};
uintptr_t kIsLocalFn = 0x17F2A50;
constexpr uint8_t kIsLocalFnBytes[] = {
    0x48, 0x8B, 0x81, 0x88, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0x40, 0x01, 0x41, 0x8D, 0x40, 0xFD, 0x83, 0xF8,
    0x06, 0x77, 0x16, 0x4C, 0x8D, 0x0D, 0x94, 0xD5, 0x80, 0xFE, 0x48, 0x98, 0x41, 0x8B, 0x94, 0x81, 0x9C, 0x2A,
    0x7F, 0x01, 0x49, 0x03, 0xD1, 0xFF, 0xE2, 0x41, 0x80, 0xF8, 0x01, 0x74, 0x03, 0x32, 0xC0, 0xC3, 0x48, 0x8B,
    0x41, 0x68, 0x48, 0x8B, 0x48, 0x40, 0x48, 0x8B, 0x41, 0x60, 0x0F, 0xB6, 0x40, 0x10, 0xC0, 0xE8, 0x02, 0x24,
    0x01, 0xC3};
uintptr_t kIsLocalTable = 0x17F2A9C;
constexpr uint8_t kIsLocalTableBytes[] = {0x84, 0x2A, 0x7F, 0x01, 0x84, 0x2A, 0x7F, 0x01, 0x84, 0x2A,
                                          0x7F, 0x01, 0x84, 0x2A, 0x7F, 0x01, 0x7B, 0x2A, 0x7F, 0x01,
                                          0x84, 0x2A, 0x7F, 0x01, 0x84, 0x2A, 0x7F, 0x01};

// The 2851 sender 0x87DD00 (only caller: X::Update 0x87CBC0 at 0x87D710).
// 0x87DD25: mov rbx,rcx ; xor r14d,r14d ; mov [rbp-0x79],r14d ;
// 0x87DD2F: cmp byte [rip+0x64F9026],r14b (-> exe+0x6D76D5C) ; je out ;
// cmp byte [rcx+0xF0],5 ; jne out ; mov rdi,[rcx+0x120] ; test rdi,rdi ; je out
uintptr_t kWallUpGate = 0x87DD25;
constexpr uint8_t kWallUpGateBytes[] = {0x48, 0x8B, 0xD9, 0x45, 0x33, 0xF6, 0x44, 0x89, 0x75, 0x87, 0x44,
                                        0x38, 0x35, 0x26, 0x90, 0x4F, 0x06, 0x0F, 0x84, 0x17, 0x02, 0x00,
                                        0x00, 0x80, 0xB9, 0xF0, 0x00, 0x00, 0x00, 0x05, 0x0F, 0x85, 0x0A,
                                        0x02, 0x00, 0x00, 0x48, 0x8B, 0xB9, 0x20, 0x01, 0x00, 0x00, 0x48,
                                        0x85, 0xFF, 0x0F, 0x84, 0xFA, 0x01, 0x00, 0x00, 0xC5, 0xE8, 0x57};
uintptr_t kWallUpCmp = 0x87DD2F;  // 44 38 35 <disp32>: 7 bytes
constexpr uint32_t kWallUpCmpDispAt = 3;
// Its call site: only for a character (type byte 1) whose actor+0x96 != 0
// (the locally controlled one).
uintptr_t kWallUpCall = 0x87D6EF;
constexpr uint8_t kWallUpCallBytes[] = {0x48, 0x8B, 0x47, 0x60, 0x48, 0x8B, 0x48, 0x08, 0x48, 0x8B,
                                        0x81, 0x88, 0x00, 0x00, 0x00, 0x80, 0x78, 0x01, 0x01, 0x75,
                                        0x11, 0x80, 0xB9, 0x96, 0x00, 0x00, 0x00, 0x00, 0x74, 0x08,
                                        0x48, 0x8B, 0xCF, 0xE8, 0xEB, 0x05, 0x00, 0x00};
uintptr_t kWallUpByte = 0x6D76D5C;  // .rdata (RW, flags 0xC0000040), zero-filled tail


// 1.0.0.3527 [V capstone on the PE, 2026-11-05]: PointClimb vtable 0x5924730 slot 7 (same prologue); the mode function and
// its callee have the same shape; the 2851 sender's gate reads the method at +0x13C and the WallUp slot at +0x168.
constexpr uint8_t kModeFn3527[] = {0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0x51, 0x68, 0x4C, 0x8B, 0xD9, 0x49, 0x8B, 0xCA, 0xE8, 0x4D, 0xB3, 0xFB, 0x00, 0x84, 0xC0, 0x0F, 0x85, 0xB2, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x43, 0x60, 0x48, 0x8B, 0x48, 0x60, 0xF6, 0x41, 0x10, 0x02, 0x0F, 0x85, 0x99, 0x00, 0x00, 0x00, 0x41, 0x83, 0xBA, 0x90, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x84, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x50, 0x01, 0x80, 0xFA, 0x01, 0x75, 0x19, 0x48, 0x8B, 0x05, 0x66, 0x79, 0x84, 0x06, 0x48, 0x8B, 0x48, 0x38, 0x48, 0x8B, 0x41, 0x50, 0x48, 0x85, 0xC0, 0x74, 0x60, 0x49, 0x3B, 0xC2, 0x75, 0x5B, 0x4D, 0x8B, 0x4A, 0x68, 0x4D, 0x8B, 0x41, 0x48, 0x4D, 0x85, 0xC0, 0x74, 0x55, 0x41, 0x80, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x00, 0x74, 0x4B, 0x8B, 0xC2, 0x83, 0xC0, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x15, 0x14, 0x9A, 0x68, 0xFF, 0x48, 0x98, 0x41, 0x8B, 0x8C, 0x82, 0x34, 0x66, 0x97, 0x00, 0x49, 0x03, 0xCA, 0xFF, 0xE1, 0x80, 0xFA, 0x01, 0x75, 0x26, 0x49, 0x8B, 0x41, 0x40, 0x80, 0xB8, 0xE9, 0x01, 0x00, 0x00, 0x00, 0x75, 0x20, 0x41, 0x80, 0xB8, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x9E, 0xC0, 0x04, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x03, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x01, 0x48, 0x83, 0xC4, 0x28, 0xC3};
constexpr uint8_t kModeFnTable3527[] = {0x00, 0x66, 0x97, 0x00, 0x00, 0x66, 0x97, 0x00, 0x00, 0x66, 0x97, 0x00, 0x00, 0x66, 0x97, 0x00, 0xFB, 0x65, 0x97, 0x00, 0x00, 0x66, 0x97, 0x00, 0x00, 0x66, 0x97, 0x00};
constexpr uint8_t kIsLocalFn3527[] = {0x48, 0x8B, 0x81, 0x88, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0x40, 0x01, 0x41, 0x8D, 0x40, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x0D, 0x24, 0xE7, 0x6C, 0xFE, 0x48, 0x98, 0x41, 0x8B, 0x94, 0x81, 0x0C, 0x19, 0x93, 0x01, 0x49, 0x03, 0xD1, 0xFF, 0xE2, 0x41, 0x80, 0xF8, 0x01, 0x74, 0x03, 0x32, 0xC0, 0xC3, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x48, 0x40, 0x48, 0x8B, 0x41, 0x60, 0x0F, 0xB6, 0x40, 0x10, 0xC0, 0xE8, 0x02, 0x24, 0x01, 0xC3};
constexpr uint8_t kIsLocalTable3527[] = {0xF4, 0x18, 0x93, 0x01, 0xF4, 0x18, 0x93, 0x01, 0xF4, 0x18, 0x93, 0x01, 0xF4, 0x18, 0x93, 0x01, 0xEB, 0x18, 0x93, 0x01, 0xF4, 0x18, 0x93, 0x01, 0xF4, 0x18, 0x93, 0x01};
constexpr uint8_t kWallUpGate3527[] = {0x48, 0x8B, 0xD9, 0x45, 0x33, 0xF6, 0x44, 0x89, 0x75, 0x87, 0x44, 0x38, 0x35, 0xAA, 0x67, 0x86, 0x06, 0x0F, 0x84, 0x0F, 0x02, 0x00, 0x00, 0x80, 0xB9, 0x3C, 0x01, 0x00, 0x00, 0x05, 0x0F, 0x85, 0x02, 0x02, 0x00, 0x00, 0x48, 0x8B, 0xB9, 0x68, 0x01, 0x00, 0x00, 0x48, 0x85, 0xFF, 0x0F, 0x84, 0xF2, 0x01, 0x00, 0x00, 0xC5, 0xE8, 0x57};
constexpr uint8_t kWallUpCall3527[] = {0x48, 0x8B, 0x47, 0x60, 0x48, 0x8B, 0x48, 0x08, 0x48, 0x8B, 0x81, 0x88, 0x00, 0x00, 0x00, 0x80, 0x78, 0x01, 0x01, 0x75, 0x11, 0x80, 0xB9, 0x96, 0x00, 0x00, 0x00, 0x00, 0x74, 0x08, 0x48, 0x8B, 0xCF, 0xE8, 0x1F, 0x1A, 0x00, 0x00};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): PointClimb vtable 0x5926780 (RTTI) slot 7 = 0x761070 (+0x660, the
// same 23-byte prologue); the mode function 0x9768D0 (+0x370, .pdata start) and its callee 0x1932500 (+0xC40, the mode
// function's call lands on it) have 3527's bytes but for their rel32 / RIP / jump-table fields (the mode function's
// `mov rax,[rip+X]` reads 0x71C0128 = 3527's 0x71BDF18 + 0x2210); the tables (0x9769A4 / 0x193254C) hold the same case
// targets moved with their function. The 2851 sender's gate 0x966025 and call site 0x9645BB moved by +0x370 (the gate
// with a new cmp displacement, the call site byte for byte); the gate still reads the method at +0x13C and the WallUp
// slot at +0x168; its cmp reads 0x71CE660 (zero-filled tail of the RW .rodata). Clock: the frame clock 0x15FA340 reads
// 0x70DBF68 (ms) and 0x70DBF78 (us), 0x13873CC the bias 0x71C03A8 (3527's + 0x2108 / + 0x2210); delay 0x710A2D8
// (remote_interp.cpp).
constexpr uint8_t kModeFn3576[] = {0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0x51, 0x68, 0x4C, 0x8B, 0xD9, 0x49, 0x8B, 0xCA, 0xE8, 0x1D, 0xBC, 0xFB, 0x00, 0x84, 0xC0, 0x0F, 0x85, 0xB2, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x43, 0x60, 0x48, 0x8B, 0x48, 0x60, 0xF6, 0x41, 0x10, 0x02, 0x0F, 0x85, 0x99, 0x00, 0x00, 0x00, 0x41, 0x83, 0xBA, 0x90, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x84, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x50, 0x01, 0x80, 0xFA, 0x01, 0x75, 0x19, 0x48, 0x8B, 0x05, 0x06, 0x98, 0x84, 0x06, 0x48, 0x8B, 0x48, 0x38, 0x48, 0x8B, 0x41, 0x50, 0x48, 0x85, 0xC0, 0x74, 0x60, 0x49, 0x3B, 0xC2, 0x75, 0x5B, 0x4D, 0x8B, 0x4A, 0x68, 0x4D, 0x8B, 0x41, 0x48, 0x4D, 0x85, 0xC0, 0x74, 0x55, 0x41, 0x80, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x00, 0x74, 0x4B, 0x8B, 0xC2, 0x83, 0xC0, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x15, 0xA4, 0x96, 0x68, 0xFF, 0x48, 0x98, 0x41, 0x8B, 0x8C, 0x82, 0xA4, 0x69, 0x97, 0x00, 0x49, 0x03, 0xCA, 0xFF, 0xE1, 0x80, 0xFA, 0x01, 0x75, 0x26, 0x49, 0x8B, 0x41, 0x40, 0x80, 0xB8, 0xE9, 0x01, 0x00, 0x00, 0x00, 0x75, 0x20, 0x41, 0x80, 0xB8, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x9E, 0xC0, 0x04, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x03, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x01, 0x48, 0x83, 0xC4, 0x28, 0xC3};
constexpr uint8_t kModeFnTable3576[] = {0x70, 0x69, 0x97, 0x00, 0x70, 0x69, 0x97, 0x00, 0x70, 0x69, 0x97, 0x00, 0x70, 0x69, 0x97, 0x00, 0x6B, 0x69, 0x97, 0x00, 0x70, 0x69, 0x97, 0x00, 0x70, 0x69, 0x97, 0x00};
constexpr uint8_t kIsLocalFn3576[] = {0x48, 0x8B, 0x81, 0x88, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0x40, 0x01, 0x41, 0x8D, 0x40, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x0D, 0xE4, 0xDA, 0x6C, 0xFE, 0x48, 0x98, 0x41, 0x8B, 0x94, 0x81, 0x4C, 0x25, 0x93, 0x01, 0x49, 0x03, 0xD1, 0xFF, 0xE2, 0x41, 0x80, 0xF8, 0x01, 0x74, 0x03, 0x32, 0xC0, 0xC3, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x48, 0x40, 0x48, 0x8B, 0x41, 0x60, 0x0F, 0xB6, 0x40, 0x10, 0xC0, 0xE8, 0x02, 0x24, 0x01, 0xC3};
constexpr uint8_t kIsLocalTable3576[] = {0x34, 0x25, 0x93, 0x01, 0x34, 0x25, 0x93, 0x01, 0x34, 0x25, 0x93, 0x01, 0x34, 0x25, 0x93, 0x01, 0x2B, 0x25, 0x93, 0x01, 0x34, 0x25, 0x93, 0x01, 0x34, 0x25, 0x93, 0x01};
constexpr uint8_t kWallUpGate3576[] = {0x48, 0x8B, 0xD9, 0x45, 0x33, 0xF6, 0x44, 0x89, 0x75, 0x87, 0x44, 0x38, 0x35, 0x2A, 0x86, 0x86, 0x06, 0x0F, 0x84, 0x0F, 0x02, 0x00, 0x00, 0x80, 0xB9, 0x3C, 0x01, 0x00, 0x00, 0x05, 0x0F, 0x85, 0x02, 0x02, 0x00, 0x00, 0x48, 0x8B, 0xB9, 0x68, 0x01, 0x00, 0x00, 0x48, 0x85, 0xFF, 0x0F, 0x84, 0xF2, 0x01, 0x00, 0x00, 0xC5, 0xE8, 0x57};
// The call site's bytes are 3527's (kWallUpCall3527): the call and its target moved together.
// Build 1.0.0.3663 (static, 2026-11-13; never run): PointClimb vtable 0x59A2B48 (RTTI) slot 7 = 0x78D520 (the same 23-byte
// prologue, .pdata start; it still reads the CC at method+0x18 and its selector / layers at +0x30 / +0x88); the mode
// function 0x9A5310 (.pdata start, 3527's + 0x2EDB0) and its callee 0x19979A0 (its call lands on it; 3527's + 0x660E0)
// have 3527's bytes but for the rel32 / RIP / image-base fields and the jump-table bases (the only parts of the 3527
// array that differ; its `mov rax,[rip+X]` reads 0x72451E8 = the world 0x72451C0 + 0x28, as 3576's 0x71C0128); the
// tables right after them (0x9A53E4 / 0x19979EC) hold the same cases (0x9A53B0 x6, 0x9A53AB; 0x19979D4 x6, 0x19979CB). The
// 2851 sender 0x993EE0: its gate 0x993F05 (+0x25, as 2976's) has 3527's bytes but for the cmp displacement (method at
// +0x13C, WallUp slot +0x168) and reads 0x72532A0 (zero-filled tail of the RW data section 0x6D56000, raw size
// 0x36CC00); its call site 0x99254B has 3527's bytes but for the call's rel32 (it calls 0x993EE0). Clock: the frame
// clock 0x163B030 (called right before the delay reads, remote_interp.cpp) reads ms 0x71600E8 at +0x20 and us
// 0x71600F0 at +0x2C (as 3576's 0x15FA360 / 0x15FA36C; now 8 bytes apart, as in 2976), divided by 1000;
// setInterpolatePositionData 0x13C5A50 reads the bias 0x7245468 at +0x1C (0x13C5A6C, as 3576's 0x13873CC); delay
// 0x718EA48 (remote_interp.cpp). The probe's offsets (wall data, TransformSync, vehicle link) are 3527's, not re-derived.
constexpr uint8_t kModeFn3663[] = {0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0x51, 0x68, 0x4C, 0x8B, 0xD9, 0x49, 0x8B, 0xCA, 0xE8, 0x7D, 0x26, 0xFF, 0x00, 0x84, 0xC0, 0x0F, 0x85, 0xB2, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x43, 0x60, 0x48, 0x8B, 0x48, 0x60, 0xF6, 0x41, 0x10, 0x02, 0x0F, 0x85, 0x99, 0x00, 0x00, 0x00, 0x41, 0x83, 0xBA, 0x90, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x84, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x50, 0x01, 0x80, 0xFA, 0x01, 0x75, 0x19, 0x48, 0x8B, 0x05, 0x86, 0xFE, 0x89, 0x06, 0x48, 0x8B, 0x48, 0x38, 0x48, 0x8B, 0x41, 0x50, 0x48, 0x85, 0xC0, 0x74, 0x60, 0x49, 0x3B, 0xC2, 0x75, 0x5B, 0x4D, 0x8B, 0x4A, 0x68, 0x4D, 0x8B, 0x41, 0x48, 0x4D, 0x85, 0xC0, 0x74, 0x55, 0x41, 0x80, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x00, 0x74, 0x4B, 0x8B, 0xC2, 0x83, 0xC0, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x15, 0x64, 0xAC, 0x65, 0xFF, 0x48, 0x98, 0x41, 0x8B, 0x8C, 0x82, 0xE4, 0x53, 0x9A, 0x00, 0x49, 0x03, 0xCA, 0xFF, 0xE1, 0x80, 0xFA, 0x01, 0x75, 0x26, 0x49, 0x8B, 0x41, 0x40, 0x80, 0xB8, 0xE9, 0x01, 0x00, 0x00, 0x00, 0x75, 0x20, 0x41, 0x80, 0xB8, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x9E, 0xC0, 0x04, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x02, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x03, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xB0, 0x01, 0x48, 0x83, 0xC4, 0x28, 0xC3};
constexpr uint8_t kModeFnTable3663[] = {0xB0, 0x53, 0x9A, 0x00, 0xB0, 0x53, 0x9A, 0x00, 0xB0, 0x53, 0x9A, 0x00, 0xB0, 0x53, 0x9A, 0x00, 0xAB, 0x53, 0x9A, 0x00, 0xB0, 0x53, 0x9A, 0x00, 0xB0, 0x53, 0x9A, 0x00};
constexpr uint8_t kIsLocalFn3663[] = {0x48, 0x8B, 0x81, 0x88, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0x40, 0x01, 0x41, 0x8D, 0x40, 0xFD, 0x83, 0xF8, 0x06, 0x77, 0x16, 0x4C, 0x8D, 0x0D, 0x44, 0x86, 0x66, 0xFE, 0x48, 0x98, 0x41, 0x8B, 0x94, 0x81, 0xEC, 0x79, 0x99, 0x01, 0x49, 0x03, 0xD1, 0xFF, 0xE2, 0x41, 0x80, 0xF8, 0x01, 0x74, 0x03, 0x32, 0xC0, 0xC3, 0x48, 0x8B, 0x41, 0x68, 0x48, 0x8B, 0x48, 0x40, 0x48, 0x8B, 0x41, 0x60, 0x0F, 0xB6, 0x40, 0x10, 0xC0, 0xE8, 0x02, 0x24, 0x01, 0xC3};
constexpr uint8_t kIsLocalTable3663[] = {0xD4, 0x79, 0x99, 0x01, 0xD4, 0x79, 0x99, 0x01, 0xD4, 0x79, 0x99, 0x01, 0xD4, 0x79, 0x99, 0x01, 0xCB, 0x79, 0x99, 0x01, 0xD4, 0x79, 0x99, 0x01, 0xD4, 0x79, 0x99, 0x01};
constexpr uint8_t kWallUpGate3663[] = {0x48, 0x8B, 0xD9, 0x45, 0x33, 0xF6, 0x44, 0x89, 0x75, 0x87, 0x44, 0x38, 0x35, 0x8A, 0xF3, 0x8B, 0x06, 0x0F, 0x84, 0x0F, 0x02, 0x00, 0x00, 0x80, 0xB9, 0x3C, 0x01, 0x00, 0x00, 0x05, 0x0F, 0x85, 0x02, 0x02, 0x00, 0x00, 0x48, 0x8B, 0xB9, 0x68, 0x01, 0x00, 0x00, 0x48, 0x85, 0xFF, 0x0F, 0x84, 0xF2, 0x01, 0x00, 0x00, 0xC5, 0xE8, 0x57};
constexpr uint8_t kWallUpCall3663[] = {0x48, 0x8B, 0x47, 0x60, 0x48, 0x8B, 0x48, 0x08, 0x48, 0x8B, 0x81, 0x88, 0x00, 0x00, 0x00, 0x80, 0x78, 0x01, 0x01, 0x75, 0x11, 0x80, 0xB9, 0x96, 0x00, 0x00, 0x00, 0x00, 0x74, 0x08, 0x48, 0x8B, 0xCF, 0xE8, 0x6F, 0x19, 0x00, 0x00};
std::span<const uint8_t> g_mode_bytes{kModeFnBytes}, g_mode_table_bytes{kModeFnTableBytes}, g_is_local_bytes{kIsLocalFnBytes},
    g_is_local_table_bytes{kIsLocalTableBytes}, g_wallup_gate_bytes{kWallUpGateBytes}, g_wallup_call_bytes{kWallUpCallBytes};
uint32_t g_code_end = rmo::kCodeEnd;

// ---------------------------------------------------------------- offsets

constexpr uint32_t kMethodCC = 0x18;     // movement method -> CharacterControl component (0x691431)
constexpr uint32_t kMethodActor = 0x20;  // movement method -> its actor (offsets.h kMethod_Actor)
constexpr uint32_t kCcActor = 0x08;
constexpr uint32_t kCcMoveController = 0xC8;  // mc
constexpr uint32_t kCcLayer0 = 0x88, kCcLayer1 = 0x90;
constexpr uint32_t kCcWallData = 0xD8;  // D
constexpr uint32_t kMcActor = 0x68;
uint32_t kMcMethod = 0xF0;    // u8 active method
uint32_t kMcMethods = 0xF8;   // method objects, 8 bytes each
constexpr uint32_t kMethodEnterOk = 0x44;
constexpr uint32_t kLayerCurrent = 0x10, kActionHash = 0x18;
constexpr uint32_t kActorKey = 0x60, kActorOwner = 0x90, kActorComps = 0x68;
constexpr uint32_t kCompsCC = 0x40, kCompsVehicle = 0x48, kCompsTS = 0x1A0;
constexpr uint32_t kVehicleLink = 0x18, kLinkKey = 0x10;
constexpr uint32_t kTsPosition = 0xB4, kTsSector = 0xC0;
constexpr float kSectorSize = 1000.0f;
constexpr uint32_t kWallState = 0xEE0, kWallId = 0x1200, kWallUp = 0x1170;
// ClientActorManager hash table (game/actor_lookup.cpp).
constexpr uint32_t kMgrTable = 0x08, kTableBucketCount = 0x88, kTableBuckets = 0x98, kTableNodes = 0xA0;
constexpr uint32_t kBucketStride = 0x100, kBucketMaxEntries = (kBucketStride - 8) / 8;
constexpr uint32_t kNodeKey = 0x04, kNodeActor = 0x08;
constexpr uint32_t kMaxScanBuckets = 1u << 18;

constexpr size_t kMaxTracked = 4;
constexpr uint32_t kSampleMs = 30;
constexpr uint64_t kMaxClimbLines = 400;
constexpr uint64_t kMaxEpisodes = 300;
constexpr uint64_t kMaxByteLines = 50;
constexpr uint16_t kEvClimb = 1;

// ---------------------------------------------------------------- state

std::atomic<bool> g_started{false}, g_on{false};
bool g_guest = false;
uintptr_t g_base = 0;
std::vector<gad::Section> g_secs;
std::vector<rmo::SectionInfo> g_info;

// 1. PointClimb
std::atomic<uint8_t> g_climb_mode{0};
std::atomic<bool> g_climb_on{false};
SafetyHookInline g_climb;
uint32_t g_climb_patch = 0;
using ModeFn = uint8_t (*)(uintptr_t mc);
ModeFn g_mode_fn = nullptr;
std::atomic<uint64_t> c_climb_calls{0};
std::atomic<uint64_t> c_climb_out[static_cast<size_t>(ClimbOut::Count)] = {};
std::atomic<uint32_t> g_climb_last_key[static_cast<size_t>(ClimbOut::Count)] = {};
p8p::EventRing<256> g_ring;
uint64_t g_climb_lines = 0, g_climb_lines_dropped = 0;

// 2. wall-up byte
std::atomic<bool> g_wallup_wanted{false}, g_wallup_on{false};
std::atomic<uint8_t> g_wallup_prev{0xFF}, g_wallup_now{0xFF};
rmo::ByteWatch g_watch;
std::atomic<uint64_t> g_watch_checks{0}, g_watch_resets{0}, g_watch_unreadable{0};
uint64_t g_byte_lines = 0;

// 3. probe
std::atomic<bool> g_probe_wanted{false}, g_probe_on{false};
struct Track {
    uint32_t key = 0;
    bool present = false;
    rmo::SampleRing<64> ring;
    rmo::Episode ep;
    rmo::ShownWatch shown;  // divergence_probe: does the update still move the buffer's shown sample?
    rmo::DivergenceWatch div;  // divergence_probe: this character against the channel
};
std::array<Track, kMaxTracked> g_tracks;
std::atomic<uint64_t> c_samples{0}, c_sample_miss{0}, c_episodes{0}, c_episodes_unlogged{0}, c_scans{0};
std::atomic<uint32_t> g_tracked_n{0}, g_tracked_key0{0};
std::atomic<uint64_t> g_trig_count[3] = {};

// 4. divergence (pendientes/p8-impl-log-async.md §3)
uintptr_t kClockBase = 0x6C8CD68;  // u64 ms (ui_pause.cpp: the frame clock 0x1416B80 reads)
uintptr_t kClockFrac = 0x6C8CD70;  // u64 us
uintptr_t kClockBias = 0x6D69438;  // i64 client -> server offset (ServerTimeInfoAck), added on client threads
uintptr_t kDelayGlobal = 0x6CB9548;  // int, the interpolation delay (remote_interp.cpp), default 200
std::atomic<bool> g_div_wanted{false}, g_div_on{false};
bool g_mode_ok = false;  // 0x88E8E0 and its callee verified: the control mode may be asked
SRWLOCK g_chan_lock = SRWLOCK_INIT;
rmo::ChannelTrail<64> g_chan;  // under g_chan_lock (network thread pushes, this thread reads a copy)
std::atomic<uint64_t> c_chan_positions{0};
rmo::DivergenceLedger g_div_ledger;  // this thread only; published through the c_div_* atomics
std::atomic<uint64_t> c_div_compared{0}, c_div_stale{0}, c_div_episodes{0}, c_div_lines{0}, c_div_short{0},
    c_div_unlogged{0};
std::atomic<uint32_t> g_div_max_cm{0};  // the largest trail distance seen (cm)

// ---------------------------------------------------------------- reads

template <class T>
bool fr(uintptr_t a, T& v) noexcept {
    return a && game::fast_read(a, &v, sizeof v);
}
bool fp(uintptr_t a, uintptr_t& v) noexcept {
    const auto p = game::fast_ptr(a);
    if (!p) return false;
    v = *p;
    return true;
}

// ---------------------------------------------------------------- 1. the detour (the game's thread)

bool call_mode_fn(uintptr_t mc, uint8_t& out) noexcept {
    __try {
        out = g_mode_fn(mc);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void climb_facts(uintptr_t m, rmo::ClimbFacts& f, uintptr_t& actor) noexcept {
    uintptr_t cc = 0, mc = 0, mc_actor = 0, cc_actor = 0;
    if (!fp(m + kMethodActor, actor) || !actor || !fp(m + kMethodCC, cc) || !cc || !fp(cc + kCcActor, cc_actor) ||
        cc_actor != actor || !fp(cc + kCcMoveController, mc) || !mc || !fp(mc + kMcActor, mc_actor) ||
        mc_actor != actor || !fr(actor + kActorKey, f.key)) {
        return;
    }
    uint8_t mode = 0;
    if (!call_mode_fn(mc, mode)) return;
    f.control_mode = mode;
    f.readable = true;
}

uint8_t climb_detour(void* method, uint8_t same_method) noexcept {
    const uint8_t orig = g_climb.unsafe_call<uint8_t>(method, same_method);
    c_climb_calls.fetch_add(1, std::memory_order_relaxed);
    if (orig) {
        c_climb_out[static_cast<size_t>(ClimbOut::OrigOk)].fetch_add(1, std::memory_order_relaxed);
        return orig;
    }
    rmo::ClimbFacts f;
    uintptr_t actor = 0;
    climb_facts(reinterpret_cast<uintptr_t>(method), f, actor);
    const auto mode = static_cast<Mode>(g_climb_mode.load(std::memory_order_relaxed));
    const ClimbOut o = rmo::climb_decide(mode, f);
    const auto i = static_cast<size_t>(o);
    c_climb_out[i].fetch_add(1, std::memory_order_relaxed);
    g_climb_last_key[i].store(f.key, std::memory_order_relaxed);
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kEvClimb;
    e.v[0] = i;
    e.v[1] = f.key;
    e.v[2] = f.readable ? f.control_mode : 0xFF;
    e.v[3] = actor;
    e.v[4] = same_method;
    g_ring.push(e);  // full: counted by the ring
    return rmo::climb_result(o, orig);
}

// ---------------------------------------------------------------- install (its own thread)

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

bool read_sections() {
    g_secs.clear();
    g_info.clear();
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!peek(g_base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || !peek(g_base + dos.e_lfanew, nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const uintptr_t first = g_base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                            nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections && i < 64; ++i) {
        IMAGE_SECTION_HEADER h{};
        if (!peek(first + i * sizeof h, h)) return false;
        gad::Section s;
        std::memcpy(s.name, h.Name, 8);
        s.va = h.VirtualAddress;
        s.size = h.Misc.VirtualSize;
        s.flags = h.Characteristics;
        g_secs.push_back(s);
        rmo::SectionInfo si;
        std::memcpy(si.name, h.Name, 8);
        si.va = h.VirtualAddress;
        si.vsize = h.Misc.VirtualSize;
        si.flags = h.Characteristics;
        g_info.push_back(si);
    }
    return !g_secs.empty();
}

struct Site {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* what;
};

// In .rsrc ([0x1000, 0x51EB000)) and byte for byte the build's code; else an error line.
bool verify(const Site& s) {
    const auto rva = static_cast<uint32_t>(s.rva);
    const auto len = static_cast<uint32_t>(s.bytes.size());
    if (!gad::in_real_code(g_secs, rva, len) || rva < rmo::kCodeBegin || rva + len > g_code_end) {
        const gad::Section* sec = gad::section_of(g_secs, rva);
        log::error("RemoteMotion: {} (exe+0x{:X}) is not inside the game's code .rsrc (section {}); REFUSED", s.what,
                   s.rva, sec ? sec->name : "none");
        return false;
    }
    if (!bytes_at(s.rva, s.bytes)) {
        log::error("RemoteMotion: {} (exe+0x{:X}, {} bytes) is not the expected code of build 2976 (another hook "
                   "there?); REFUSED",
                   s.what, s.rva, s.bytes.size());
        return false;
    }
    return true;
}

// The control-mode function alone (divergence_probe asks it from this thread; read only, under SEH).
bool mode_code_ok(bool quiet) {
    if (quiet) {
        return bytes_at(kModeFn, g_mode_bytes) && bytes_at(kModeFnTable, g_mode_table_bytes) &&
               bytes_at(kIsLocalFn, g_is_local_bytes) && bytes_at(kIsLocalTable, g_is_local_table_bytes);
    }
    return verify({kModeFn, g_mode_bytes, "the control-mode function 0x88E8E0 (whole body)"}) &&
           verify({kModeFnTable, g_mode_table_bytes, "0x88E8E0's jump table"}) &&
           verify({kIsLocalFn, g_is_local_bytes, "its callee 0x17F2A50 (whole body)"}) &&
           verify({kIsLocalTable, g_is_local_table_bytes, "0x17F2A50's jump table"});
}

bool climb_code_ok(bool quiet) {
    if (quiet) {
        return bytes_at(kPointClimbEnter, kPointClimbHead) && bytes_at(kModeFn, g_mode_bytes) &&
               bytes_at(kModeFnTable, g_mode_table_bytes) && bytes_at(kIsLocalFn, g_is_local_bytes) &&
               bytes_at(kIsLocalTable, g_is_local_table_bytes);
    }
    return verify({kPointClimbEnter, kPointClimbHead, "PointClimb::Enter 0x691400 (23-byte prologue)"}) &&
           verify({kModeFn, g_mode_bytes, "the control-mode function 0x88E8E0 (whole body)"}) &&
           verify({kModeFnTable, g_mode_table_bytes, "0x88E8E0's jump table"}) &&
           verify({kIsLocalFn, g_is_local_bytes, "its callee 0x17F2A50 (whole body)"}) &&
           verify({kIsLocalTable, g_is_local_table_bytes, "0x17F2A50's jump table"});
}

bool wallup_code_ok(bool quiet) {
    if (quiet) return bytes_at(kWallUpGate, g_wallup_gate_bytes) && bytes_at(kWallUpCall, g_wallup_call_bytes);
    return verify({kWallUpGate, g_wallup_gate_bytes, "the 2851 sender's gate 0x87DD25..0x87DD5C"}) &&
           verify({kWallUpCall, g_wallup_call_bytes, "its call site 0x87D6EF..0x87D715"});
}

bool install_climb() {
    if (!climb_code_ok(false)) return false;
    g_mode_fn = reinterpret_cast<ModeFn>(g_base + kModeFn);
    auto whole = [](const std::vector<uint8_t>& o) {
        return std::find(std::begin(kPointClimbBoundaries), std::end(kPointClimbBoundaries), o.size()) !=
                   std::end(kPointClimbBoundaries) &&
               o.size() <= sizeof kPointClimbHead && std::memcmp(o.data(), kPointClimbHead, o.size()) == 0;
    };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(g_base + kPointClimbEnter, reinterpret_cast<void*>(&climb_detour), whole,
                                  "RemoteMotion", "PointClimb::Enter");
    if (!h) {
        log::error("RemoteMotion: the hook on PointClimb::Enter (exe+0x{:X}) could not be prepared ({}); REFUSED",
                   kPointClimbEnter, game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("RemoteMotion: the hook on PointClimb::Enter would patch {} bytes, not a whole number of the "
                   "verified instructions; REFUSED, nothing written",
                   orig.size());
        return false;
    }
    g_climb_patch = static_cast<uint32_t>(orig.size());
    g_climb = std::move(*h);  // the detour calls through it: in place before enabling
    if (!g_climb.enable()) {
        log::error("RemoteMotion: the hook on PointClimb::Enter could not be enabled; REFUSED");
        g_climb = {};
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- 2. the byte (its own thread)

bool byte_read(uintptr_t a, uint8_t& v) noexcept { return game::fast_read(a, &v, 1); }

bool byte_write_one(uintptr_t a) noexcept {
    __try {
        *reinterpret_cast<volatile uint8_t*>(a) = 1;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool install_wallup() {
    if (!wallup_code_ok(false)) return false;
    // The address the game itself reads: from the live cmp's displacement.
    int32_t disp = 0;
    if (!peek(g_base + kWallUpCmp + kWallUpCmpDispAt, disp)) return false;
    const uintptr_t target_rva = kWallUpCmp + 7 + static_cast<intptr_t>(disp);
    if (target_rva != kWallUpByte) {
        log::error("RemoteMotion: the cmp at exe+0x{:X} reads exe+0x{:X}, not exe+0x{:X}; wallup_send REFUSED",
                   kWallUpCmp, target_rva, kWallUpByte);
        return false;
    }
    const rmo::ByteSite site = rmo::check_data_byte(g_info, static_cast<uint32_t>(kWallUpByte));
    const rmo::SectionInfo* sec = rmo::section_info_of(g_info, static_cast<uint32_t>(kWallUpByte));
    if (site != rmo::ByteSite::Ok) {
        log::error("RemoteMotion: exe+0x{:X} is {} (section {}); wallup_send REFUSED, nothing written", kWallUpByte,
                   rmo::byte_site_name(site), sec ? sec->name : "none");
        return false;
    }
    const uintptr_t a = g_base + kWallUpByte;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof mbi) != sizeof mbi ||
        !rmo::page_writable_data(mbi.State, mbi.Protect)) {
        log::error("RemoteMotion: the page of exe+0x{:X} is not committed read/write data (state 0x{:X}, protect "
                   "0x{:X}); wallup_send REFUSED, nothing written",
                   kWallUpByte, static_cast<uint32_t>(mbi.State), static_cast<uint32_t>(mbi.Protect));
        return false;
    }
    uint8_t prev = 0xFF;
    if (!byte_read(a, prev)) {
        log::error("RemoteMotion: exe+0x{:X} is not readable; wallup_send REFUSED", kWallUpByte);
        return false;
    }
    g_wallup_prev.store(prev);
    if (prev > 1) {
        log::error("RemoteMotion: exe+0x{:X} holds {} (a bool was expected: 0 or 1); wallup_send REFUSED, nothing "
                   "written",
                   kWallUpByte, prev);
        return false;
    }
    uint8_t back = 0xFF;
    if (!byte_write_one(a) || !byte_read(a, back) || back != 1) {
        log::error("RemoteMotion: writing 1 to exe+0x{:X} failed (read back {}); wallup_send OFF", kWallUpByte, back);
        return false;
    }
    g_wallup_now.store(back);
    log::info("RemoteMotion: wallup_send ON: byte exe+0x{:X} ({} 0x{:X}+0x{:X}, flags 0x{:08X}, page protect 0x{:X}) "
              "{} -> 1 | the 2851 sender 0x87DD00 now sends UpdateWallUpDataReq while this client's character is in "
              "method 5 (WallUp); the other gates (0x87DD3C method 5, X+0x120, the call site's local character, "
              "the logged-in controlled actor, ClientNet+0x112 connected) are the game's",
              kWallUpByte, sec->name, sec->va, sec->vsize, sec->flags, static_cast<uint32_t>(mbi.Protect), prev);
    return true;
}

void watch_byte() {
    const uintptr_t a = g_base + kWallUpByte;
    uint8_t v = 0xFF;
    const bool ok = byte_read(a, v);
    const bool rewrite = g_watch.observe(ok, v);
    g_watch_checks.store(g_watch.checks, std::memory_order_relaxed);
    g_watch_unreadable.store(g_watch.unreadable, std::memory_order_relaxed);
    if (ok) g_wallup_now.store(v, std::memory_order_relaxed);
    if (!rewrite) return;
    g_watch_resets.store(g_watch.resets, std::memory_order_relaxed);
    uint8_t back = 0xFF;
    const bool written = byte_write_one(a) && byte_read(a, back) && back == 1;
    if (written) g_wallup_now.store(1, std::memory_order_relaxed);
    if (g_byte_lines++ < kMaxByteLines) {
        log::warn("RemoteMotion: the game reset exe+0x{:X} to {} (reset #{}, check #{}); {}", kWallUpByte, v,
                  g_watch.resets, g_watch.checks, written ? "written 1 again" : "writing 1 again FAILED");
    }
}

// ---------------------------------------------------------------- 3. the probe (its own thread)

bool actor_manager(uintptr_t& mgr, uintptr_t& local_actor) noexcept {
    uintptr_t world = 0, vt = 0;
    const auto* profile = game::reader_profile();
    if (!profile || !fp(g_base + profile->world_system, world) || !world ||
        !fp(world + g2976::kWorldSystem_ActorManager, mgr) || !mgr || !fr(mgr, vt) ||
        vt != g_base + profile->vt_actor_manager) {
        return false;
    }
    local_actor = 0;
    fp(mgr + g2976::kActorManager_ControlledActor, local_actor);
    return true;
}

struct Table {
    uint32_t buckets = 0;
    uintptr_t bucket_base = 0, nodes = 0;
};

bool table_of(uintptr_t mgr, Table& t) noexcept {
    uintptr_t table = 0;
    return fp(mgr + kMgrTable, table) && table && fr(table + kTableBucketCount, t.buckets) && t.buckets &&
           t.buckets <= (1u << 24) && fp(table + kTableBuckets, t.bucket_base) && t.bucket_base &&
           fp(table + kTableNodes, t.nodes) && t.nodes;
}

uintptr_t node_actor(const Table& t, uint32_t idx, uint32_t key) noexcept {
    uintptr_t node = 0, actor = 0;
    uint32_t nk = 0, ak = 0;
    if (!fp(t.nodes + static_cast<uintptr_t>(idx) * 8, node) || !node || !fr(node + kNodeKey, nk) || nk != key ||
        !fp(node + kNodeActor, actor) || !actor || !fr(actor + kActorKey, ak) || ak != key) {
        return 0;
    }
    return actor;
}

uintptr_t find_actor_fast(const Table& t, uint32_t key) noexcept {
    const uintptr_t bucket = t.bucket_base + static_cast<uintptr_t>(key % t.buckets) * kBucketStride;
    uint32_t n = 0;
    if (!fr(bucket, n)) return 0;
    for (uint32_t i = 0; i < n && i < kBucketMaxEntries; ++i) {
        uint32_t k = 0, idx = 0;
        if (!fr(bucket + 8 + i * 8, k) || k != key || !fr(bucket + 0xC + i * 8, idx)) continue;
        return node_actor(t, idx, key);
    }
    return 0;
}

// Every second: the other player's character(s) in this client's actor manager.
void scan_candidates() {
    uintptr_t mgr = 0, local = 0;
    Table t;
    if (!actor_manager(mgr, local) || !table_of(mgr, t)) return;
    c_scans.fetch_add(1, std::memory_order_relaxed);
    uint32_t local_key = 0;
    if (local) fr(local + kActorKey, local_key);
    std::array<uint32_t, kMaxTracked> found{};
    size_t nfound = 0;
    const uint32_t nb = std::min(t.buckets, kMaxScanBuckets);
    for (uint32_t b = 0; b < nb && nfound < kMaxTracked; ++b) {
        const uintptr_t bucket = t.bucket_base + static_cast<uintptr_t>(b) * kBucketStride;
        uint32_t n = 0;
        if (!fr(bucket, n) || n == 0) continue;
        for (uint32_t i = 0; i < n && i < kBucketMaxEntries && nfound < kMaxTracked; ++i) {
            uint32_t k = 0, idx = 0;
            if (!fr(bucket + 8 + i * 8, k) || !rmo::is_player_character_key(k) || !fr(bucket + 0xC + i * 8, idx)) {
                continue;
            }
            const uintptr_t actor = node_actor(t, idx, k);
            uint32_t owner = 0;
            if (!actor || !fr(actor + kActorOwner, owner)) continue;
            if (rmo::is_remote_player_candidate(k, owner, actor, local, local_key)) found[nfound++] = k;
        }
    }
    // Keep the tracks of keys still present; new keys take free slots.
    for (Track& tr : g_tracks) {
        tr.present = tr.key && std::find(found.begin(), found.begin() + nfound, tr.key) != found.begin() + nfound;
    }
    for (size_t i = 0; i < nfound; ++i) {
        const bool known = std::any_of(g_tracks.begin(), g_tracks.end(), [&](const Track& tr) { return tr.key == found[i]; });
        if (known) continue;
        for (Track& tr : g_tracks) {
            if (tr.key && tr.present) continue;
            if (tr.key && (tr.ep.active() || tr.div.over())) continue;  // let an open episode / divergence close first
            const uint32_t old = tr.key;
            tr = Track{};
            tr.key = found[i];
            tr.present = true;
            log::info("RemoteMotion probe: tracking the other player's character 0x{:08X}{}", found[i],
                      old ? std::format(" (instead of 0x{:08X}, gone)", old) : std::string());
            break;
        }
    }
    uint32_t n = 0, k0 = 0;
    for (const Track& tr : g_tracks) {
        if (tr.key && tr.present) {
            if (!n) k0 = tr.key;
            ++n;
        }
    }
    g_tracked_n.store(n, std::memory_order_relaxed);
    g_tracked_key0.store(k0, std::memory_order_relaxed);
}

rmo::Sample read_sample(uintptr_t actor, uint32_t now_ms) noexcept {
    rmo::Sample s;
    s.t_ms = now_ms;
    uintptr_t comps = 0, cc = 0, mc = 0;
    if (!fp(actor + kActorComps, comps) || !comps || !fp(comps + kCompsCC, cc) || !cc ||
        !fp(cc + kCcMoveController, mc) || !mc || !fr(mc + kMcMethod, s.method)) {
        return s;
    }
    s.ok = true;
    uintptr_t mobj = 0;
    if (s.method < 64 && fp(mc + kMcMethods + 8ull * s.method, mobj) && mobj) {
        uint8_t e = 0xFF;
        if (fr(mobj + kMethodEnterOk, e)) s.enter_ok = e;
    }
    for (int i = 0; i < 2; ++i) {
        uintptr_t layer = 0, cur = 0;
        uint32_t h = 0;
        if (fp(cc + (i ? kCcLayer1 : kCcLayer0), layer) && layer && fp(layer + kLayerCurrent, cur) && cur &&
            fr(cur + kActionHash, h)) {
            (i ? s.act1 : s.act0) = h;
        }
    }
    uintptr_t vc = 0, link = 0;
    if (fp(comps + kCompsVehicle, vc) && vc && fp(vc + kVehicleLink, link) && link) fr(link + kLinkKey, s.link);
    uintptr_t ts = 0;
    float p[3] = {};
    int16_t sector[2] = {};
    if (fp(comps + kCompsTS, ts) && ts && game::fast_read(ts + kTsPosition, p, sizeof p) &&
        game::fast_read(ts + kTsSector, sector, sizeof sector) && std::isfinite(p[0]) && std::isfinite(p[1]) &&
        std::isfinite(p[2])) {
        s.pos[0] = p[0] + sector[0] * kSectorSize;
        s.pos[1] = p[1];
        s.pos[2] = p[2] + sector[1] * kSectorSize;
        s.pos_ok = true;
    }
    uintptr_t d = 0;
    if (fp(cc + kCcWallData, d) && d) {
        fr(d + kWallState, s.wall_state);
        fr(d + kWallId, s.wall_id);
        float up[3] = {};
        if (game::fast_read(d + kWallUp, up, sizeof up) && std::isfinite(up[0]) && std::isfinite(up[1]) &&
            std::isfinite(up[2])) {
            std::memcpy(s.wall_up, up, sizeof up);
        }
    }
    return s;
}

uint32_t now_ms() { return static_cast<uint32_t>(p8_now_us() / 1000); }

void log_episode(Track& tr, bool early) {
    const uint64_t n = c_episodes.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n > kMaxEpisodes) {
        c_episodes_unlogged.fetch_add(1, std::memory_order_relaxed);
    } else {
        for (const std::string& line : tr.ep.lines(n, early)) log::info("{}", line);
    }
    tr.ep.close();
}

// ---------------------------------------------------------------- 4. divergence (this thread)

// The mod's reads for rmo::read_interp (SEH-guarded fast reads).
struct FastMem {
    bool ptr(uintptr_t a, uintptr_t& v) const noexcept { return fp(a, v); }
    bool u8(uintptr_t a, uint8_t& v) const noexcept { return fr(a, v); }
    bool u32(uintptr_t a, uint32_t& v) const noexcept { return fr(a, v); }
    bool u64(uintptr_t a, uint64_t& v) const noexcept { return fr(a, v); }
    bool vec3(uintptr_t a, float (&v)[3]) const noexcept { return a && game::fast_read(a, v, sizeof v); }
};

// actor -> its movement controller (the probe's chain: [[actor+0x68]+0x40]+0xC8), with the same identity
// checks climb_facts makes before the game's 0x88E8E0 is called on it: [CC+8] == actor and [mc+0x68] == actor
// (rmo::mc_identity_ok). 0 when anything does not match.
uintptr_t mc_of(uintptr_t actor) noexcept {
    uintptr_t comps = 0, cc = 0, mc = 0, cc_actor = 0, mc_actor = 0;
    if (!actor || !fp(actor + kActorComps, comps) || !comps || !fp(comps + kCompsCC, cc) || !cc ||
        !fp(cc + kCcActor, cc_actor) || !fp(cc + kCcMoveController, mc) || !mc || !fp(mc + kMcActor, mc_actor)) {
        return 0;
    }
    return rmo::mc_identity_ok(actor, cc_actor, mc, mc_actor) ? mc : 0;
}

uint64_t now_ms64() { return p8_now_us() / 1000; }

// The client's clock as the interpolation sees it on a client thread: frame ms + the server bias.
bool game_now(uint64_t& now) noexcept {
    uint64_t base = 0, frac = 0;
    int64_t bias = 0;
    if (!fr(g_base + kClockBase, base) || !fr(g_base + kClockFrac, frac) || !fr(g_base + kClockBias, bias)) {
        return false;
    }
    now = base + frac / 1000 + static_cast<uint64_t>(bias);
    return true;
}

struct DivCandidate {
    Track* tr = nullptr;
    uintptr_t actor = 0;  // 0: the track has no actor this sample (gone / not found): its watch closes
    rmo::Sample s;
    rmo::ChannelDistance cd;
};

void divergence_line(const DivCandidate& c, const rmo::DivergenceWatch::Step& step, uintptr_t local) {
    rmo::DivergenceFacts f;
    f.step = step;
    if (c.tr) f.key = c.tr->key;
    if (step.kind == rmo::DivergenceWatch::Kind::Line && c.tr && c.actor) {
        f.actor = c.actor;
        f.s = c.s;
        f.cd = c.cd;
        f.mc = mc_of(c.actor);  // 0 unless CC and mc both name this actor: then no game call, no buffer read
        uint8_t mode = 0xFF;
        if (f.mc && g_mode_ok && g_mode_fn && call_mode_fn(f.mc, mode)) f.control_mode = mode;
        if (f.mc) f.iv = rmo::read_interp(FastMem{}, f.mc + rmo::kInterpPosBuffer);
        int32_t delay = 0;
        f.now_ok = game_now(f.game_now) && fr(g_base + kDelayGlobal, delay);
        f.delay = delay >= 0 && delay <= 60000 ? static_cast<uint32_t>(delay) : 200;
        f.shown_since_ms = c.tr->shown.since_ms(now_ms64());
        if (local) {
            const rmo::Sample ls = read_sample(local, now_ms());
            f.local_ok = ls.ok;
            f.local_method = ls.method;
            f.local_act0 = ls.act0;
            f.local_act1 = ls.act1;
        }
    }
    log::warn("{}", rmo::divergence_text(f));
}

// Every sample: EACH tracked character against the channel's trail, with its own watch. The channel does
// not say which actor it is; normally there is one candidate (the other player's character) and the key is
// in every line, while a closest-of-N choice could hide the real one behind another candidate. One shared
// ledger (episode numbers, line budget).
void divergence_tick(const std::array<DivCandidate, kMaxTracked>& cands, size_t n, uintptr_t local) {
    rmo::ChannelTrail<64> chan;
    AcquireSRWLockShared(&g_chan_lock);
    chan = g_chan;
    ReleaseSRWLockShared(&g_chan_lock);
    const uint64_t now = now_ms64();
    for (size_t i = 0; i < n; ++i) {
        DivCandidate c = cands[i];
        bool valid = false;
        if (c.actor && c.s.pos_ok) {
            c.cd = chan.distance(c.s.pos, now);
            valid = c.cd.ok;
            if (valid) {
                c_div_compared.fetch_add(1, std::memory_order_relaxed);
                const auto cm = static_cast<uint32_t>(std::min(c.cd.trail * 100.0f, 4.0e9f));
                if (cm > g_div_max_cm.load(std::memory_order_relaxed)) g_div_max_cm.store(cm, std::memory_order_relaxed);
            } else if (chan.size()) {
                c_div_stale.fetch_add(1, std::memory_order_relaxed);
            }
        }
        const auto step = c.tr->div.observe(now, valid, valid ? c.cd.trail : 0.0f, g_div_ledger);
        if (step.kind != rmo::DivergenceWatch::Kind::None) divergence_line(c, step, local);
    }
    c_div_episodes.store(g_div_ledger.episodes, std::memory_order_relaxed);
    c_div_lines.store(g_div_ledger.lines, std::memory_order_relaxed);
    c_div_short.store(g_div_ledger.short_spikes, std::memory_order_relaxed);
    c_div_unlogged.store(g_div_ledger.unlogged, std::memory_order_relaxed);
}

void probe_tick() {
    uintptr_t mgr = 0, local = 0;
    Table t;
    const bool table_ok = actor_manager(mgr, local) && table_of(mgr, t);
    const uint32_t now = now_ms();
    const bool episodes = g_probe_on.load(std::memory_order_relaxed);
    const bool div = g_div_on.load(std::memory_order_relaxed);
    std::array<DivCandidate, kMaxTracked> cands{};
    size_t ncand = 0;
    for (Track& tr : g_tracks) {
        if (!tr.key) continue;
        if (!tr.present) {  // gone at the last scan
            if (tr.ep.active()) log_episode(tr, true);
            tr.ring.clear();
            tr.shown.reset();
            if (div && ncand < cands.size()) cands[ncand++] = DivCandidate{&tr, 0, {}, {}};  // closes its watch
            continue;
        }
        const uintptr_t actor = table_ok ? find_actor_fast(t, tr.key) : 0;
        if (!actor) {
            c_sample_miss.fetch_add(1, std::memory_order_relaxed);
            if (tr.ep.active()) log_episode(tr, true);
            tr.ring.clear();
            tr.shown.reset();
            if (div && ncand < cands.size()) cands[ncand++] = DivCandidate{&tr, 0, {}, {}};
            continue;
        }
        const rmo::Sample s = read_sample(actor, now);
        c_samples.fetch_add(1, std::memory_order_relaxed);
        if (div) {
            // Two reads: the shown sample's ts of the position buffer (does the per-frame update still write it?).
            uint64_t shown_ts = 0;
            const uintptr_t mc = mc_of(actor);
            const bool ok = mc && fr(mc + rmo::kInterpPosBuffer + rmo::kInterpShown + rmo::kInterpSampleTs, shown_ts);
            tr.shown.observe(now_ms64(), ok, shown_ts);
            if (ncand < cands.size()) cands[ncand++] = DivCandidate{&tr, actor, s, {}};
        }
        if (episodes) {
            const rmo::Sample* prev = tr.ring.last();
            const uint8_t trig = prev ? rmo::trigger_of(*prev, s) : 0;
            if (trig) {
                for (int b = 0; b < 3; ++b) {
                    if (trig & (1 << b)) g_trig_count[b].fetch_add(1, std::memory_order_relaxed);
                }
            }
            if (tr.ep.active()) {
                tr.ep.add(s);
                if (trig) tr.ep.retrigger(now, trig);
            } else if (trig) {
                tr.ep.start(tr.key, now, trig, *prev, s, tr.ring);
                tr.ep.add(s);
            }
        }
        tr.ring.push(s);
        if (episodes && tr.ep.done(now)) log_episode(tr, false);
    }
    if (div) divergence_tick(cands, ncand, local);
}

// ---------------------------------------------------------------- drain / summary

void drain() {
    p8p::Event e;
    for (size_t n = 0; n < 60 && g_ring.pop(e); ++n) {
        if (e.kind != kEvClimb) continue;
        if (g_climb_lines >= kMaxClimbLines) {
            ++g_climb_lines_dropped;
            continue;
        }
        ++g_climb_lines;
        const auto o = static_cast<ClimbOut>(e.v[0]);
        log::info("RemoteMotion climb [{}] {}: PointClimb::Enter(same {}) of actor 0x{:X} key 0x{:08X} control mode "
                  "{}: {}",
                  rmo::mode_name(static_cast<Mode>(g_climb_mode.load())), p8_when(e.qpc_us), e.v[4], e.v[3], e.v[1],
                  e.v[2] == 0xFF ? std::string("?") : std::to_string(e.v[2]), rmo::climb_out_name(o));
    }
}

void wait_for_world() {
    const uint64_t t0 = GetTickCount64();
    uint64_t last_line = t0;
    log::info("RemoteMotion: waiting for the local player in the world before hooking (never at start-up or on the "
              "title screen)");
    for (int stable = 0; stable < 6;) {
        Sleep(500);
        uintptr_t mgr = 0, local = 0, avt = 0;
        const bool in = actor_manager(mgr, local) && local && peek(local, avt) &&
                        avt == g_base + (game::reader_profile() ? game::reader_profile()->vt_controlled_actor : g2976::kVtControlledActor);
        stable = in ? stable + 1 : 0;
        const uint64_t now = GetTickCount64();
        if (now - last_line >= 60000) {
            log::info("RemoteMotion start-up: still waiting for the world after {} s", (now - t0) / 1000);
            last_line = now;
        }
    }
    log::info("RemoteMotion: the local player is in the world ({} s): installing", (GetTickCount64() - t0) / 1000);
}

DWORD WINAPI motion_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto build = game::current_build();
    if (build == game::Build::unsupported ||
        (!game::legacy_layout() && build != game::Build::v3576 && build != game::Build::v3663)) {
        log::error("RemoteMotion: unsupported game build; remote_climb / wallup_send / dismount_probe stay off");
        return 0;
    }
    if (build == game::Build::v3663) {
        kPointClimbEnter = 0x78D520;
        kModeFn = 0x9A5310;
        kModeFnTable = 0x9A53E4;
        kIsLocalFn = 0x19979A0;
        kIsLocalTable = 0x19979EC;
        kWallUpGate = 0x993F05;
        kWallUpCmp = 0x993F0F;
        kWallUpCall = 0x99254B;
        kWallUpByte = 0x72532A0;
        kClockBase = 0x71600E8;
        kClockFrac = 0x71600F0;
        kClockBias = 0x7245468;
        kDelayGlobal = 0x718EA48;
        kMcMethod = 0x13C;
        kMcMethods = 0x140;
        g_mode_bytes = kModeFn3663;
        g_mode_table_bytes = kModeFnTable3663;
        g_is_local_bytes = kIsLocalFn3663;
        g_is_local_table_bytes = kIsLocalTable3663;
        g_wallup_gate_bytes = kWallUpGate3663;
        g_wallup_call_bytes = kWallUpCall3663;
        g_code_end = 0x5613000;  // the first section = [0x1000, 0x5613000), execute and not write
    }
    if (build == game::Build::v3576) {
        kPointClimbEnter = 0x761070;
        kModeFn = 0x9768D0;
        kModeFnTable = 0x9769A4;
        kIsLocalFn = 0x1932500;
        kIsLocalTable = 0x193254C;
        kWallUpGate = 0x966025;
        kWallUpCmp = 0x96602F;
        kWallUpCall = 0x9645BB;
        kWallUpByte = 0x71CE660;
        kClockBase = 0x70DBF68;
        kClockFrac = 0x70DBF78;
        kClockBias = 0x71C03A8;
        kDelayGlobal = 0x710A2D8;
        kMcMethod = 0x13C;
        kMcMethods = 0x140;
        g_mode_bytes = kModeFn3576;
        g_mode_table_bytes = kModeFnTable3576;
        g_is_local_bytes = kIsLocalFn3576;
        g_is_local_table_bytes = kIsLocalTable3576;
        g_wallup_gate_bytes = kWallUpGate3576;
        g_wallup_call_bytes = kWallUpCall3527;
        g_code_end = 0x5597000;  // .text1 = [0x1000, 0x5597000), execute and not write
    }
    if (build == game::Build::v3527) {
        kPointClimbEnter = 0x760A10;
        kModeFn = 0x976560;
        kModeFnTable = 0x976634;
        kIsLocalFn = 0x19318C0;
        kIsLocalTable = 0x193190C;
        kWallUpGate = 0x965CB5;
        kWallUpCmp = 0x965CBF;
        kWallUpCall = 0x96424B;
        kWallUpByte = 0x71CC470;
        kClockBase = 0x70D9E60;
        kClockFrac = 0x70D9E70;
        kClockBias = 0x71BE198;
        kDelayGlobal = 0x71081C8;
        kMcMethod = 0x13C;
        kMcMethods = 0x140;
        g_mode_bytes = kModeFn3527;
        g_mode_table_bytes = kModeFnTable3527;
        g_is_local_bytes = kIsLocalFn3527;
        g_is_local_table_bytes = kIsLocalTable3527;
        g_wallup_gate_bytes = kWallUpGate3527;
        g_wallup_call_bytes = kWallUpCall3527;
        g_code_end = 0x5595000;
    }
    if (!read_sections()) {
        log::error("RemoteMotion: the game's section table is unreadable; everything stays off");
        return 0;
    }
    const auto climb = static_cast<Mode>(g_climb_mode.load());
    const bool wallup = g_wallup_wanted.load(), probe = g_probe_wanted.load(), div = g_div_wanted.load();
    bool ready = false;
    for (int i = 0; i < 24000 && !ready; ++i) {
        ready = (climb == Mode::Off || climb_code_ok(true)) && (!wallup || wallup_code_ok(true));
        if (!ready) Sleep(5);
    }
    if (!ready) log::warn("RemoteMotion: the game's code is not the expected one after 2 minutes; checking once more");
    wait_for_world();

    if (climb != Mode::Off) {
        g_climb_on = install_climb();
        log::info("RemoteMotion: remote_climb {} {}", rmo::mode_name(climb),
                  g_climb_on ? std::format("ON ({}): inline hook at PointClimb::Enter exe+0x{:X}, patch {} of the 23 "
                                           "verified bytes, inside .rsrc; control mode by the game's 0x{:X} (verified) | "
                                           "{}",
                                           g_guest ? "guest" : "host", kPointClimbEnter, g_climb_patch, kModeFn,
                                           climb == Mode::On
                                               ? "a failed Enter of a remote player's character (mode 2, key 0xA01...) "
                                                 "returns 1"
                                               : "probe: counts failed Enters by control mode and key, changes nothing")
                             : std::string("OFF (see the error above)"));
    }
    if (wallup) {
        g_wallup_on = install_wallup();
        if (!g_wallup_on) log::warn("RemoteMotion: wallup_send OFF (see the error above)");
    }
    if (probe) {
        g_probe_on = true;
        log::info("RemoteMotion: dismount_probe ON ({}): read only, every {} ms, the other player's character(s) "
                  "(0xA01... with an owning user, not this client's); episodes on ride methods 6/7/10 or the vehicle "
                  "link (also PointClimb 18 and WallUp 5), 1 s before to 5 s after",
                  g_guest ? "guest" : "host", kSampleMs);
    }
    if (div) {
        // The control mode is asked from this thread only if the game's function is the verified one.
        if (!g_mode_fn && mode_code_ok(false)) g_mode_fn = reinterpret_cast<ModeFn>(g_base + kModeFn);
        g_mode_ok = g_mode_fn != nullptr;
        g_div_on = true;
        log::info("RemoteMotion: divergence_probe ON ({}): read only, every {} ms, the other player's character in "
                  "memory (TS+0xB4 + sector) against this mod's channel position (the HUD's) | over {:.1f} m to the "
                  "channel's last {} ms for more than {} ms: one line per second (at most {}), and one at its end | "
                  "control mode {}",
                  g_guest ? "guest" : "host", kSampleMs, rmo::kDivergenceThresholdM, rmo::kTrailMs,
                  rmo::kDivergenceHoldMs, rmo::kDivergenceMaxLines,
                  g_mode_ok ? "by the game's 0x88E8E0 (verified)" : "NOT asked (0x88E8E0 not verified: '?')");
    }
    g_on.store(g_climb_on || g_wallup_on || g_probe_on || g_div_on);
    if (!g_on.load()) {
        log::warn("RemoteMotion: nothing installed");
        return 0;
    }
    const bool sampling = g_probe_on || g_div_on;
    uint64_t last_sec = GetTickCount64(), last_summary = last_sec;
    if (sampling) scan_candidates();
    for (;;) {
        Sleep(sampling ? kSampleMs : 200);
        if (sampling) probe_tick();
        const uint64_t now = GetTickCount64();
        if (now - last_sec >= 1000) {
            last_sec = now;
            if (g_wallup_on) watch_byte();
            if (sampling) scan_candidates();
            drain();
        }
        if (now - last_summary >= 60000) {
            last_summary = now;
            drain();
            log::info("RemoteMotion summary: {}{}", remote_motion_describe(),
                      g_climb_lines_dropped ? std::format(" | climb lines not written (budget) {}", g_climb_lines_dropped)
                                            : std::string());
        }
    }
}

}  // namespace

void remote_motion_start(const RemoteMotionOptions& opt, bool guest) {
    const rmo::ParsedMode c = rmo::parse_mode(opt.remote_climb);
    if (!c.known) log::warn("RemoteMotion: remote_climb='{}' is not 0, probe or 1; it stays off", opt.remote_climb);
    if (c.mode == Mode::Off && !opt.wallup_send && !opt.dismount_probe && !opt.divergence_probe) return;
    if (g_started.exchange(true)) return;
    g_climb_mode.store(static_cast<uint8_t>(c.mode));
    g_wallup_wanted.store(opt.wallup_send);
    g_probe_wanted.store(opt.dismount_probe);
    g_div_wanted.store(opt.divergence_probe);
    g_guest = guest;
    CloseHandle(CreateThread(nullptr, 0, motion_thread, nullptr, 0, nullptr));
}

bool remote_motion_active() { return g_on.load(); }

void remote_motion_channel_position(float x, float y, float z) noexcept {
    if (!g_div_wanted.load(std::memory_order_relaxed)) return;
    const float p[3] = {x, y, z};
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return;
    const uint64_t t = now_ms64();
    AcquireSRWLockExclusive(&g_chan_lock);
    g_chan.push(t, p);
    ReleaseSRWLockExclusive(&g_chan_lock);
    c_chan_positions.fetch_add(1, std::memory_order_relaxed);
}

std::string remote_motion_describe() {
    if (!g_started.load()) return {};
    auto out = [](ClimbOut o) { return c_climb_out[static_cast<size_t>(o)].load(); };
    auto last = [](ClimbOut o) { return g_climb_last_key[static_cast<size_t>(o)].load(); };
    return std::format(
        "remote_climb {} (hook {}): Enter calls {}, original ok {}, forced {} (last 0x{:08X}), would force {} (last "
        "0x{:08X}), failed mode 1 {} / mode 3 {} / other mode {} / mode 2 not a player {} (last 0x{:08X}) / unreadable "
        "{}, events lost {} | wallup_send {} (byte {} -> now {}, checks {}, game resets {}, unreadable {}) | "
        "dismount_probe {}: tracked {} (0x{:08X}), samples {}, misses {}, triggers ride {} climb {} wallup {}, episodes "
        "{} (not logged {}), scans {}",
        rmo::mode_name(static_cast<Mode>(g_climb_mode.load())), g_climb_on.load() ? "on" : "off", c_climb_calls.load(),
        out(ClimbOut::OrigOk), out(ClimbOut::Forced), last(ClimbOut::Forced), out(ClimbOut::WouldForce),
        last(ClimbOut::WouldForce), out(ClimbOut::FailMode1), out(ClimbOut::FailMode3), out(ClimbOut::FailModeOther),
        out(ClimbOut::FailMode2Other), last(ClimbOut::FailMode2Other), out(ClimbOut::Unreadable), g_ring.dropped(),
        g_wallup_wanted.load() ? (g_wallup_on.load() ? "on" : "OFF") : "0", g_wallup_prev.load(), g_wallup_now.load(),
        g_watch_checks.load(), g_watch_resets.load(), g_watch_unreadable.load(),
        g_probe_wanted.load() ? (g_probe_on.load() ? "on" : "off") : "0", g_tracked_n.load(), g_tracked_key0.load(),
        c_samples.load(), c_sample_miss.load(), g_trig_count[0].load(), g_trig_count[1].load(), g_trig_count[2].load(),
        c_episodes.load(), c_episodes_unlogged.load(), c_scans.load()) +
           std::format(" | divergence_probe {}: channel positions {}, compared {}, no fresh channel {}, largest {:.2f} m, "
                       "episodes {} (lines {}, not logged {}), short spikes <= {} ms {}",
                       g_div_wanted.load() ? (g_div_on.load() ? "on" : "off") : "0", c_chan_positions.load(),
                       c_div_compared.load(), c_div_stale.load(), g_div_max_cm.load() / 100.0, c_div_episodes.load(),
                       c_div_lines.load(), c_div_unlogged.load(), rmo::kDivergenceHoldMs, c_div_short.load());
}

}  // namespace cdmp::session2
