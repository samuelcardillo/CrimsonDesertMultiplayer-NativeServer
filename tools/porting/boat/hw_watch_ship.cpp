// shiptrace.dll - diagnostic only (build 1.0.0.3576), loaded into the GUEST copy by hand.
// Watches the client ship actor's TransformSync position x (TS+0xEC, sector-local f32) with a hardware write
// breakpoint (DR0) on every thread, and records which code writes it. A write that moves the ship by more than
// kJumpM metres (a reset) is logged with its unwound stack (exe RVAs). Normal writers are counted per site.
// Nothing of the game is called; the only change to the process is DR0/DR7 and one VEH. Stops itself after
// kMaxJumps jumps, after kMaxMinutes, or when <dll dir>\shiptrace.stop exists (DRs cleared, VEH removed).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
constexpr uintptr_t kWorldSystem = 0x71C0100;  // 3576
constexpr uint32_t kKey = 0xB0100E51;
constexpr float kJumpM = 30.0f;
constexpr int kMaxJumps = 4;
constexpr int kMaxMinutes = 50;
constexpr int kFrames = 28;

uintptr_t g_base = 0;
uintptr_t g_watch = 0;  // TS+0xEC
uintptr_t g_ts = 0;
PVOID g_veh = nullptr;
DWORD g_self_tid = 0;
wchar_t g_dir[MAX_PATH] = {};

struct Event {
    uint64_t rip;
    float old_x, old_z, new_x, new_z;
    uint64_t frames[kFrames];
    int n;
    DWORD tid;
};
Event g_events[8];
std::atomic<int> g_event_count{0};
std::atomic<uint64_t> g_hits{0};
float g_last_x = NAN, g_last_z = NAN;
struct Site { std::atomic<uint64_t> rip; std::atomic<uint64_t> n; };
Site g_sites[32];

bool rd(uintptr_t a, void* out, size_t n) {
    __try {
        memcpy(out, reinterpret_cast<const void*>(a), n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
template <class T> bool rdv(uintptr_t a, T* v) { return rd(a, v, sizeof(T)); }

bool world_xz(float* x, float* z) {
    float p[3];
    int16_t s[2];
    if (!rd(g_ts + 0xEC, p, sizeof p) || !rd(g_ts + 0xF8, s, sizeof s)) return false;
    *x = p[0] + s[0] * 1000.0f;
    *z = p[2] + s[1] * 1000.0f;
    return true;
}

void note_site(uint64_t rip) {
    for (auto& s : g_sites) {
        uint64_t cur = s.rip.load();
        if (cur == rip) { s.n++; return; }
        if (cur == 0) {
            uint64_t z = 0;
            if (s.rip.compare_exchange_strong(z, rip) || s.rip.load() == rip) { s.n++; return; }
        }
    }
}

LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    if (!(c->Dr6 & 1)) return EXCEPTION_CONTINUE_SEARCH;
    c->Dr6 = 0;
    g_hits++;
    note_site(c->Rip);
    float x, z;
    if (!world_xz(&x, &z)) return EXCEPTION_CONTINUE_EXECUTION;
    if (!std::isnan(g_last_x)) {
        const float d = std::sqrt((x - g_last_x) * (x - g_last_x) + (z - g_last_z) * (z - g_last_z));
        const int i = g_event_count.load();
        const float ax = std::fabs(x - g_last_x), az = std::fabs(z - g_last_z);
        const bool sector_artifact = std::fabs(ax - 1000.0f) < 20.0f || std::fabs(az - 1000.0f) < 20.0f;
        if (d > kJumpM && !sector_artifact && i < kMaxJumps) {
            Event& e = g_events[i];
            e.rip = c->Rip;
            e.old_x = g_last_x; e.old_z = g_last_z; e.new_x = x; e.new_z = z;
            e.tid = GetCurrentThreadId();
            e.n = 0;
            CONTEXT u = *c;
            __try {
                for (int f = 0; f < kFrames && u.Rip; ++f) {
                    e.frames[e.n++] = u.Rip;
                    DWORD64 image = 0;
                    PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(u.Rip, &image, nullptr);
                    if (fn) {
                        PVOID hd = nullptr;
                        DWORD64 est = 0;
                        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, u.Rip, fn, &u, &hd, &est, nullptr);
                    } else {
                        u.Rip = *reinterpret_cast<DWORD64*>(u.Rsp);
                        u.Rsp += 8;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
            g_event_count.store(i + 1);
        }
    }
    g_last_x = x;
    g_last_z = z;
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
                    c.Dr0 = g_watch;
                    c.Dr7 = (c.Dr7 & ~0xF0003ull) | 1ull | (1ull << 16) | (3ull << 18);  // L0, write, 4 bytes
                } else if (c.Dr0 == g_watch) {
                    c.Dr0 = 0;
                    c.Dr7 &= ~0xF0003ull;
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

uintptr_t find_actor() {
    uintptr_t world = 0, mgr = 0, t = 0, buckets = 0, nodes = 0;
    uint32_t n = 0;
    if (!rdv(g_base + kWorldSystem, &world) || !world || !rdv(world + 0x30, &mgr) || !mgr || !rdv(mgr + 8, &t) || !t ||
        !rdv(t + 0x88, &n) || !n || n > (1u << 24) || !rdv(t + 0x98, &buckets) || !rdv(t + 0xA0, &nodes))
        return 0;
    const uintptr_t b = buckets + static_cast<uintptr_t>(kKey % n) * 0x100;
    uint32_t c = 0;
    if (!rdv(b, &c)) return 0;
    for (uint32_t i = 0; i < c && i < 31; ++i) {
        uint32_t k = 0, idx = 0;
        if (!rdv(b + 8 + i * 8, &k) || !rdv(b + 0xC + i * 8, &idx) || k != kKey) continue;
        uintptr_t node = 0, actor = 0;
        if (!rdv(nodes + static_cast<uintptr_t>(idx) * 8, &node) || !node || !rdv(node + 8, &actor)) return 0;
        return actor;
    }
    return 0;
}

const char* rva(uint64_t a, char* buf, size_t cap) {
    if (a >= g_base && a < g_base + 0x10000000) snprintf(buf, cap, "exe+0x%llX", static_cast<unsigned long long>(a - g_base));
    else snprintf(buf, cap, "0x%llX", static_cast<unsigned long long>(a));
    return buf;
}

DWORD WINAPI worker(LPVOID) {
    g_self_tid = GetCurrentThreadId();
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    wchar_t path[MAX_PATH];
    wcscpy_s(path, g_dir);
    wcscat_s(path, L"shiptrace.log");
    _wfopen_s(&g_log, path, L"a");
    const uintptr_t actor = find_actor();
    uintptr_t comps = 0;
    if (!actor || !rdv(actor + 0x68, &comps) || !comps || !rdv(comps + 0x1A0, &g_ts) || !g_ts) {
        logf("ship 0x%08X not found (actor %p): nothing installed", kKey, reinterpret_cast<void*>(actor));
        return 0;
    }
    g_watch = g_ts + 0xEC;
    float x = 0, z = 0;
    world_xz(&x, &z);
    g_veh = AddVectoredExceptionHandler(1, veh);
    const int n = set_drs(true);
    logf("installed: ship 0x%08X actor %p TS %p watch %p at (%.1f, %.1f); DR0 on %d threads; VEH %p", kKey,
         reinterpret_cast<void*>(actor), reinterpret_cast<void*>(g_ts), reinterpret_cast<void*>(g_watch), x, z, n, g_veh);
    wchar_t stop[MAX_PATH];
    wcscpy_s(stop, g_dir);
    wcscat_s(stop, L"shiptrace.stop");
    int logged = 0;
    const ULONGLONG t0 = GetTickCount64();
    ULONGLONG last_status = t0, last_rearm = t0;
    for (;;) {
        Sleep(200);
        const int ev = g_event_count.load();
        for (; logged < ev; ++logged) {
            const Event& e = g_events[logged];
            char b[64];
            logf("JUMP %d: (%.1f, %.1f) -> (%.1f, %.1f) by thread %lu, writer %s", logged + 1, e.old_x, e.old_z, e.new_x,
                 e.new_z, e.tid, rva(e.rip, b, sizeof b));
            for (int f = 0; f < e.n; ++f) logf("    #%02d %s", f, rva(e.frames[f], b, sizeof b));
        }
        const ULONGLONG now = GetTickCount64();
        if (now - last_rearm > 5000) {
            set_drs(true);
            last_rearm = now;
        }
        if (now - last_status > 30000) {
            char sites[1024] = {};
            for (auto& s : g_sites) {
                const uint64_t r = s.rip.load();
                if (!r) break;
                char b[64], one[96];
                snprintf(one, sizeof one, " %s x%llu", rva(r, b, sizeof b), static_cast<unsigned long long>(s.n.load()));
                strncat_s(sites, one, _TRUNCATE);
            }
            world_xz(&x, &z);
            logf("status: hits %llu jumps %d ship (%.1f, %.1f) writers:%s", static_cast<unsigned long long>(g_hits.load()),
                 ev, x, z, sites);
            last_status = now;
        }
        if (GetFileAttributesW(stop) != INVALID_FILE_ATTRIBUTES || ev >= kMaxJumps || now - t0 > kMaxMinutes * 60000ull) break;
    }
    const int m = set_drs(false);
    Sleep(500);
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    logf("stopped: DR0 cleared on %d threads, VEH removed, hits %llu jumps %d", m, static_cast<unsigned long long>(g_hits.load()),
         g_event_count.load());
    fclose(g_log);
    g_log = nullptr;
    return 0;
}
}  // namespace

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        GetModuleFileNameW(h, g_dir, MAX_PATH);
        if (wchar_t* s = wcsrchr(g_dir, L'\\')) s[1] = 0;
        HANDLE t = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
