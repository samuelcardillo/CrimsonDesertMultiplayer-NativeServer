// hw_watch.dll - diagnostic only, loaded by hand (tools/porting/boat/inject.py) into a local test copy of the game.
// One hardware write breakpoint (DR0) on every thread of the process plus one VEH. Nothing of the game is called and
// nothing else is written. Configuration: <dll path without extension>.cfg, one line:
//   <address hex> <length 1|2|4|8> <mode sites|jump> [x offset] [z offset] [sector offset or -1]
//   sites: logs the unwound stack of each distinct writer (up to 8 sites), then counts.
//   req:   a byte written below 0x0F (a TransformSync position request type) is logged with its stack and the
//          request position (sector-local f32 x3 + i16 sector x2 at address-0x10), up to 6.
//   jump:  floats at address+x and address+z (plus i16 sector pair at +sector, 1000 m) are read after each write;
//          a move of more than 30 m (not a sector wrap) is logged with the writer's stack (up to 6).
// Log: <dll path without extension>.log (shared, readable while it runs). Stops after 50 minutes, after 6 jumps, or
// when <dll path without extension>.stop exists: DR0 cleared on all threads, VEH removed.
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
constexpr int kFrames = 28;
constexpr int kMaxEvents = 8;
constexpr float kJumpM = 30.0f;

uintptr_t g_base = 0, g_watch = 0;
int g_len = 4, g_mode = 0;  // 0 sites, 1 jump, 2 req
long g_xoff = 0, g_zoff = 8, g_secoff = -1;
PVOID g_veh = nullptr;
DWORD g_self_tid = 0;
wchar_t g_stem[MAX_PATH] = {};

struct Event {
    uint64_t rip;
    float ox, oz, nx, nz;
    uint64_t frames[kFrames];
    int n;
    DWORD tid;
    uint64_t regs[16];   // rax rcx rdx rbx rsp rbp rsi rdi r8..r15
    uint64_t extra;      // qword at [rbp + x offset] (sites mode; 0 if unreadable)
};
Event g_events[kMaxEvents];
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

bool read_xz(float* x, float* z) {
    if (!rd(g_watch + g_xoff, x, 4) || !rd(g_watch + g_zoff, z, 4)) return false;
    if (g_secoff >= 0) {
        int16_t s[2];
        if (!rd(g_watch + g_secoff, s, sizeof s)) return false;
        *x += s[0] * 1000.0f;
        *z += s[1] * 1000.0f;
    }
    return true;
}

// Returns true the first time this rip is seen.
bool note_site(uint64_t rip) {
    for (auto& s : g_sites) {
        uint64_t cur = s.rip.load();
        if (cur == rip) { s.n++; return false; }
        if (cur == 0) {
            uint64_t z = 0;
            if (s.rip.compare_exchange_strong(z, rip)) { s.n++; return true; }
            if (s.rip.load() == rip) { s.n++; return false; }
        }
    }
    return false;
}

void capture(const CONTEXT* c, float ox, float oz, float nx, float nz) {
    const int i = g_event_count.load();
    if (i >= kMaxEvents) return;
    Event& e = g_events[i];
    e.rip = c->Rip;
    e.ox = ox; e.oz = oz; e.nx = nx; e.nz = nz;
    e.tid = GetCurrentThreadId();
    e.n = 0;
    const uint64_t rg[16] = {c->Rax, c->Rcx, c->Rdx, c->Rbx, c->Rsp, c->Rbp, c->Rsi, c->Rdi,
                             c->R8, c->R9, c->R10, c->R11, c->R12, c->R13, c->R14, c->R15};
    memcpy(e.regs, rg, sizeof rg);
    e.extra = 0;
    if (g_mode == 0 && g_xoff) rd(c->Rbp + g_xoff, &e.extra, 8);
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

LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    if (!(c->Dr6 & 1)) return EXCEPTION_CONTINUE_SEARCH;
    c->Dr6 = 0;
    g_hits++;
    const bool first = note_site(c->Rip);
    if (g_mode == 0) {
        if (first) capture(c, 0, 0, 0, 0);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (g_mode == 2) {
        uint8_t type = 0xFF;
        float q[3] = {};
        int16_t sec[2] = {};
        if (rd(g_watch, &type, 1) && type < 0x0F && rd(g_watch - 0x10, q, sizeof q) && rd(g_watch - 0x4, sec, sizeof sec))
            capture(c, static_cast<float>(type), 0, q[0] + sec[0] * 1000.0f, q[2] + sec[1] * 1000.0f);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    float x, z;
    if (!read_xz(&x, &z)) return EXCEPTION_CONTINUE_EXECUTION;
    if (!std::isnan(g_last_x)) {
        const float ax = std::fabs(x - g_last_x), az = std::fabs(z - g_last_z);
        const bool wrap = std::fabs(ax - 1000.0f) < 20.0f || std::fabs(az - 1000.0f) < 20.0f;
        if (std::sqrt(ax * ax + az * az) > kJumpM && !wrap) capture(c, g_last_x, g_last_z, x, z);
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
    const uint64_t len_bits = g_len == 1 ? 0 : g_len == 2 ? 1 : g_len == 8 ? 2 : 3;
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
                    c.Dr7 = (c.Dr7 & ~0xF0003ull) | 1ull | (1ull << 16) | (len_bits << 18);
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

const char* rva(uint64_t a, char* buf, size_t cap) {
    if (a >= g_base && a < g_base + 0x10000000) snprintf(buf, cap, "exe+0x%llX", static_cast<unsigned long long>(a - g_base));
    else snprintf(buf, cap, "0x%llX", static_cast<unsigned long long>(a));
    return buf;
}

DWORD WINAPI worker(LPVOID) {
    g_self_tid = GetCurrentThreadId();
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    wchar_t path[MAX_PATH];
    swprintf_s(path, L"%s.log", g_stem);
    g_log = _wfsopen(path, L"a", _SH_DENYNO);
    swprintf_s(path, L"%s.cfg", g_stem);
    FILE* cfg = _wfsopen(path, L"r", _SH_DENYNO);
    char mode[16] = {};
    unsigned long long addr = 0;
    if (!cfg || fscanf_s(cfg, "%llx %d %15s %ld %ld %ld", &addr, &g_len, mode, static_cast<unsigned>(sizeof mode), &g_xoff,
                         &g_zoff, &g_secoff) < 3) {
        logf("no or bad config: nothing installed");
        if (cfg) fclose(cfg);
        return 0;
    }
    fclose(cfg);
    g_watch = static_cast<uintptr_t>(addr);
    g_mode = strcmp(mode, "jump") == 0 ? 1 : strcmp(mode, "req") == 0 ? 2 : 0;
    uint8_t probe;
    if (!rd(g_watch, &probe, 1)) {
        logf("address %p not readable: nothing installed", reinterpret_cast<void*>(g_watch));
        return 0;
    }
    if (g_mode == 1) read_xz(&g_last_x, &g_last_z);
    g_veh = AddVectoredExceptionHandler(1, veh);
    const int n = set_drs(true);
    logf("installed: watch %p len %d mode %s (x +%ld z +%ld sector %ld) at (%.1f, %.1f); DR0 on %d threads",
         reinterpret_cast<void*>(g_watch), g_len, g_mode == 1 ? "jump" : g_mode == 2 ? "req" : "sites", g_xoff, g_zoff, g_secoff, g_last_x, g_last_z, n);
    swprintf_s(path, L"%s.stop", g_stem);
    int logged = 0;
    const ULONGLONG t0 = GetTickCount64();
    ULONGLONG last_status = t0, last_rearm = t0;
    for (;;) {
        Sleep(200);
        const int ev = g_event_count.load();
        for (; logged < ev; ++logged) {
            const Event& e = g_events[logged];
            char b[64];
            if (g_mode == 1)
                logf("JUMP %d: (%.1f, %.1f) -> (%.1f, %.1f) thread %lu writer %s", logged + 1, e.ox, e.oz, e.nx, e.nz, e.tid,
                     rva(e.rip, b, sizeof b));
            else if (g_mode == 2)
                logf("REQUEST %d: type %.0f to (%.1f, %.1f) thread %lu writer %s", logged + 1, e.ox, e.nx, e.nz, e.tid,
                     rva(e.rip, b, sizeof b));
            else
            {
                logf("SITE %d: thread %lu writer %s", logged + 1, e.tid, rva(e.rip, b, sizeof b));
                logf("    rax %llX rcx %llX rdx %llX rbx %llX rsp %llX rbp %llX rsi %llX rdi %llX", e.regs[0], e.regs[1], e.regs[2],
                     e.regs[3], e.regs[4], e.regs[5], e.regs[6], e.regs[7]);
                logf("    r8 %llX r9 %llX r10 %llX r11 %llX r12 %llX r13 %llX r14 %llX r15 %llX  [rbp%+ld] %llX", e.regs[8], e.regs[9],
                     e.regs[10], e.regs[11], e.regs[12], e.regs[13], e.regs[14], e.regs[15], g_xoff, e.extra);
            }
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
            float x = 0, z = 0;
            if (g_mode == 1) read_xz(&x, &z);
            logf("status: hits %llu events %d at (%.1f, %.1f) writers:%s", static_cast<unsigned long long>(g_hits.load()), ev,
                 x, z, sites);
            last_status = now;
        }
        const bool full = g_mode != 0 ? ev >= 6 : false;
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES || full || now - t0 > 50 * 60000ull) break;
    }
    const int m = set_drs(false);
    Sleep(500);
    if (g_veh) RemoveVectoredExceptionHandler(g_veh);
    logf("stopped: DR0 cleared on %d threads, VEH removed, hits %llu events %d", m,
         static_cast<unsigned long long>(g_hits.load()), g_event_count.load());
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
