// vehicle_follow_test.dll - diagnostic experiment only (build 1.0.0.3576), loaded by hand into the GUEST test copy.
// Every frame the guest's client puts the host's vehicle actor (the ship's hierarchy parent, type 5) on the guest's own
// ship with a TransformSync position/rotation request of type 7 (0xB03BB0 / 0xB03FB0, from its character update).
// This replaces, for that one actor and those two requests only, the position and rotation with the host's pose that
// the client already stores as the vehicle's last network pose (TS+0x550 world vec3, TS+0x55C quat).
// Mechanism: execute breakpoints (DR0 = 0xB03BB0, DR1 = 0xB03FB0) on every thread + a VEH; the VEH edits the caller's
// pose argument and resumes with RF. No code bytes are written. Config <stem>.cfg: "<vehicle key hex> <seconds>".
// Stops after the given seconds or when <stem>.stop exists (DRs cleared, VEH removed). Log: <stem>.log.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <share.h>
#include <tlhelp32.h>
#include <atomic>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
constexpr uintptr_t kWorldSystem = 0x71C0100;
constexpr uintptr_t kSetPosition = 0xB03BB0;  // (TS*, const Pos* {f32 x,y,z; i16 sx,sz}, u8 type, ...)
constexpr uintptr_t kSetRotation = 0xB03FB0;  // (TS*, const Quat*, u8 type, ...)
constexpr uint8_t kType = 7;

uintptr_t g_base = 0, g_ts = 0;
uint32_t g_key = 0;
PVOID g_veh = nullptr;
DWORD g_self_tid = 0;
wchar_t g_stem[MAX_PATH] = {};
std::atomic<uint64_t> g_pos_hits{0}, g_pos_swapped{0}, g_rot_swapped{0}, g_other{0};

bool rd(uintptr_t a, void* out, size_t n) {
    __try {
        memcpy(out, reinterpret_cast<const void*>(a), n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
bool wr(uintptr_t a, const void* in, size_t n) {
    __try {
        memcpy(reinterpret_cast<void*>(a), in, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
template <class T> bool rdv(uintptr_t a, T* v) { return rd(a, v, sizeof(T)); }

LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    const uint64_t d6 = c->Dr6;
    if (!(d6 & 3)) return EXCEPTION_CONTINUE_SEARCH;
    c->Dr6 = 0;
    c->EFlags |= 0x10000;  // RF: resume past the execute breakpoint
    if (c->Rcx != g_ts || (c->R8 & 0xFF) != kType) {
        g_other++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (d6 & 1) {
        g_pos_hits++;
        float net[3];
        if (rd(g_ts + 0x550, net, sizeof net) && std::isfinite(net[0]) && std::isfinite(net[2]) && net[0] != 0.0f) {
            const int16_t sx = static_cast<int16_t>(static_cast<int>(net[0] / 1000.0f));
            const int16_t sz = static_cast<int16_t>(static_cast<int>(net[2] / 1000.0f));
            float p[3] = {net[0] - sx * 1000.0f, net[1], net[2] - sz * 1000.0f};
            int16_t s[2] = {sx, sz};
            if (wr(c->Rdx, p, sizeof p) && wr(c->Rdx + 0xC, s, sizeof s)) g_pos_swapped++;
        }
    } else {
        float q[4];
        if (rd(g_ts + 0x55C, q, sizeof q)) {
            const float n = q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3];
            if (std::fabs(n - 1.0f) < 0.02f && wr(c->Rdx, q, sizeof q)) g_rot_swapped++;
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

int set_drs(bool on) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    THREADENTRY32 te{sizeof te};
    const DWORD pid = GetCurrentProcessId();
    int n = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == g_self_tid) continue;
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!t) continue;
        if (SuspendThread(t) != static_cast<DWORD>(-1)) {
            CONTEXT c{};
            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(t, &c)) {
                if (on) {
                    c.Dr0 = g_base + kSetPosition;
                    c.Dr1 = g_base + kSetRotation;
                    c.Dr7 = (c.Dr7 & ~0xFF000Full) | 1ull | 4ull;  // L0, L1, execute, length 1
                } else {
                    if (c.Dr0 == g_base + kSetPosition) c.Dr0 = 0;
                    if (c.Dr1 == g_base + kSetRotation) c.Dr1 = 0;
                    c.Dr7 &= ~0xFF000Full;
                }
                if (SetThreadContext(t, &c)) ++n;
            }
            ResumeThread(t);
        }
        CloseHandle(t);
    }
    CloseHandle(snap);
    return n;
}

FILE* g_log = nullptr;
void logf(const char* fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list a;
    va_start(a, fmt);
    vfprintf(g_log, fmt, a);
    va_end(a);
    fputc('\n', g_log);
    fflush(g_log);
}

uintptr_t find_actor(uint32_t key) {
    uintptr_t world = 0, mgr = 0, t = 0, buckets = 0, nodes = 0;
    uint32_t n = 0;
    if (!rdv(g_base + kWorldSystem, &world) || !world || !rdv(world + 0x30, &mgr) || !mgr || !rdv(mgr + 8, &t) || !t ||
        !rdv(t + 0x88, &n) || !n || n > (1u << 24) || !rdv(t + 0x98, &buckets) || !rdv(t + 0xA0, &nodes))
        return 0;
    const uintptr_t b = buckets + static_cast<uintptr_t>(key % n) * 0x100;
    uint32_t c = 0;
    if (!rdv(b, &c)) return 0;
    for (uint32_t i = 0; i < c && i < 31; ++i) {
        uint32_t k = 0, idx = 0;
        if (!rdv(b + 8 + i * 8, &k) || !rdv(b + 0xC + i * 8, &idx) || k != key) continue;
        uintptr_t node = 0, actor = 0;
        if (!rdv(nodes + static_cast<uintptr_t>(idx) * 8, &node) || !node || !rdv(node + 8, &actor)) return 0;
        return actor;
    }
    return 0;
}

DWORD WINAPI worker(LPVOID) {
    g_self_tid = GetCurrentThreadId();
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    wchar_t path[MAX_PATH];
    swprintf_s(path, L"%s.log", g_stem);
    g_log = _wfsopen(path, L"a", _SH_DENYNO);
    swprintf_s(path, L"%s.cfg", g_stem);
    FILE* cfg = _wfsopen(path, L"r", _SH_DENYNO);
    unsigned key = 0;
    int seconds = 0;
    if (!cfg || fscanf_s(cfg, "%x %d", &key, &seconds) != 2 || seconds <= 0) {
        logf("no or bad config: nothing installed");
        if (cfg) fclose(cfg);
        return 0;
    }
    fclose(cfg);
    g_key = key;
    const uintptr_t actor = find_actor(g_key);
    uintptr_t comps = 0;
    if (!actor || !rdv(actor + 0x68, &comps) || !comps || !rdv(comps + 0x1A0, &g_ts) || !g_ts) {
        logf("actor 0x%08X not found: nothing installed", g_key);
        return 0;
    }
    float net[3] = {};
    rd(g_ts + 0x550, net, sizeof net);
    g_veh = AddVectoredExceptionHandler(1, veh);
    const int n = set_drs(true);
    logf("installed for %d s: vehicle 0x%08X TS %p, network pose (%.1f, %.1f, %.1f); DR0/DR1 on %d threads", seconds, g_key,
         reinterpret_cast<void*>(g_ts), net[0], net[1], net[2], n);
    swprintf_s(path, L"%s.stop", g_stem);
    const ULONGLONG t0 = GetTickCount64();
    ULONGLONG last = t0, rearm = t0;
    for (;;) {
        Sleep(200);
        const ULONGLONG now = GetTickCount64();
        if (now - rearm > 5000) {
            set_drs(true);
            rearm = now;
        }
        if (now - last >= 5000) {
            rd(g_ts + 0x550, net, sizeof net);
            logf("calls: ours %llu (position swapped %llu, rotation swapped %llu), others %llu; network (%.1f, %.1f)",
                 static_cast<unsigned long long>(g_pos_hits.load()), static_cast<unsigned long long>(g_pos_swapped.load()),
                 static_cast<unsigned long long>(g_rot_swapped.load()), static_cast<unsigned long long>(g_other.load()), net[0],
                 net[2]);
            last = now;
        }
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES || now - t0 > static_cast<ULONGLONG>(seconds) * 1000) break;
    }
    const int m = set_drs(false);
    Sleep(500);
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    logf("stopped: DRs cleared on %d threads, VEH removed; position swapped %llu, rotation swapped %llu", m,
         static_cast<unsigned long long>(g_pos_swapped.load()), static_cast<unsigned long long>(g_rot_swapped.load()));
    fclose(g_log);
    g_log = nullptr;
    return 0;
}
}  // namespace

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        GetModuleFileNameW(h, g_stem, MAX_PATH);
        if (wchar_t* dot = wcsrchr(g_stem, L'.')) *dot = 0;
        HANDLE t = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
