// Offline ABI replay of the installed 3527 ToTarget constructor. No game
// process is opened. Code is read from --exe, checked, copied into this test
// process and discarded. No executable bytes are saved or embedded here.
// The only call is to a test-owned actor's vfE8. The emitter/TLS paths are
// deliberately outside this test.
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/sha256.h"

namespace {
int g_failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); ++g_failures; } } while (0)

constexpr uint32_t kCtor = 0x2D04590, kCtorSize = 0x4B;
constexpr uint32_t kBaseVtable = 0x5EEC860, kTargetVtable = 0x5EEC840;
// The executables this replay is verified against. The replayed code hashes the same on both.
struct KnownExe {
    uint64_t size;
    const char* sha256;
    uint32_t timestamp, image_size;
};
constexpr KnownExe kExes[] = {
    {328899480, "dc4237f21d6ce1e49f8e5d6fa89bf803fbbe6549123078efdc393265c7bf6841", 0x6AEA07A6, 0x13EB2000},  // 1.0.0.3527
    {327116696, "25f24e06a1f886e9310fd290f9462f66b480a5e7763d1fe156bfddaa8d1992b9", 0x6AEB7D59, 0x13CFF000},  // 1.0.0.3549
};
constexpr const char* kCtorHash = "ce9c28c5ebcc7c82b3abb76cbd4f164859736c7e21e0d6238ab3b86dff1c70d2";

class PeReader {
    std::ifstream input_;
    std::vector<IMAGE_SECTION_HEADER> sections_;
    IMAGE_DATA_DIRECTORY exceptions_{};
    const KnownExe* exe_ = nullptr;
    std::vector<uint8_t> at(uint64_t offset, size_t size) {
        if (offset > exe_->size || size > exe_->size - offset) throw std::runtime_error("PE read outside file");
        std::vector<uint8_t> bytes(size);
        input_.clear();
        input_.seekg(static_cast<std::streamoff>(offset));
        input_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (!input_) throw std::runtime_error("short PE read");
        return bytes;
    }
    template <class T> T object(uint64_t offset) {
        const auto bytes = at(offset, sizeof(T));
        T result{};
        std::memcpy(&result, bytes.data(), sizeof result);
        return result;
    }
public:
    explicit PeReader(const std::filesystem::path& path) : input_(path, std::ios::binary) {
        if (!input_) throw std::runtime_error("cannot open --exe");
        const uint64_t file_size = std::filesystem::file_size(path);
        for (const KnownExe& known : kExes) {
            if (known.size == file_size) exe_ = &known;
        }
        if (!exe_) throw std::runtime_error("--exe is not a verified file size (3527 or 3549)");
        cdmp::sha256::Hasher hash;
        std::vector<uint8_t> block(1 << 20);
        uint64_t remaining = exe_->size;
        while (remaining) {
            const size_t count = static_cast<size_t>(std::min<uint64_t>(remaining, block.size()));
            input_.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(count));
            if (!input_) throw std::runtime_error("short executable hash read");
            hash.update(std::span<const uint8_t>(block.data(), count));
            remaining -= count;
        }
        if (cdmp::sha256::hex(hash.finish()) != exe_->sha256) throw std::runtime_error("executable SHA256 mismatch");
        const auto dos = object<IMAGE_DOS_HEADER>(0);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0x40 || dos.e_lfanew > 0x100000)
            throw std::runtime_error("invalid DOS header");
        const auto nt = object<IMAGE_NT_HEADERS64>(static_cast<uint64_t>(dos.e_lfanew));
        if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt.FileHeader.TimeDateStamp != exe_->timestamp || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt.OptionalHeader.ImageBase != 0x140000000ull || nt.OptionalHeader.SizeOfImage != exe_->image_size ||
            nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > 96)
            throw std::runtime_error("unexpected PE profile");
        const uint64_t table = static_cast<uint64_t>(dos.e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                               nt.FileHeader.SizeOfOptionalHeader;
        for (uint32_t n = 0; n < nt.FileHeader.NumberOfSections; ++n)
            sections_.push_back(object<IMAGE_SECTION_HEADER>(table + n * sizeof(IMAGE_SECTION_HEADER)));
        exceptions_ = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    }
    std::vector<uint8_t> rva(uint32_t address, size_t size) {
        for (const auto& section : sections_) {
            if (address < section.VirtualAddress) continue;
            const uint64_t delta = static_cast<uint64_t>(address) - section.VirtualAddress;
            if (delta + size <= section.SizeOfRawData) return at(section.PointerToRawData + delta, size);
        }
        throw std::runtime_error("RVA is outside raw section data");
    }
    RUNTIME_FUNCTION function(uint32_t address) {
        if (!exceptions_.Size || exceptions_.Size > 0x1000000) throw std::runtime_error("invalid unwind table");
        const auto bytes = rva(exceptions_.VirtualAddress, exceptions_.Size);
        for (size_t offset = 0; offset + sizeof(RUNTIME_FUNCTION) <= bytes.size(); offset += sizeof(RUNTIME_FUNCTION)) {
            RUNTIME_FUNCTION f{};
            std::memcpy(&f, bytes.data() + offset, sizeof f);
            if (f.BeginAddress == address) return f;
        }
        throw std::runtime_error("constructor unwind record missing");
    }
};

struct Allocation {
    uint8_t* bytes = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Allocation() { if (!bytes) throw std::runtime_error("cannot allocate local replay"); }
    ~Allocation() { VirtualFree(bytes, 0, MEM_RELEASE); }
    Allocation(const Allocation&) = delete;
    Allocation& operator=(const Allocation&) = delete;
};

class ConstructorReplay {
    Allocation memory_;
    RUNTIME_FUNCTION unwind_{0, kCtorSize, 0x100};
    bool registered_ = false;
public:
    // Two inert data addresses replace the native vtable addresses. Neither
    // table is dereferenced or callable; the constructor only stores them.
    uintptr_t target_vtable() const { return reinterpret_cast<uintptr_t>(memory_.bytes + 0x1000); }
    uint8_t* code() const { return memory_.bytes; }
    explicit ConstructorReplay(PeReader& pe) {
        const auto f = pe.function(kCtor);
        if (f.EndAddress != kCtor + kCtorSize) throw std::runtime_error("unexpected constructor boundary");
        auto bytes = pe.rva(kCtor, kCtorSize);
        if (cdmp::sha256::hex(cdmp::sha256::of(bytes)) != kCtorHash)
            throw std::runtime_error("constructor recipe SHA256 mismatch");
        auto native_unwind = pe.rva(f.UnwindData, 8);
        if (native_unwind[0] != 0x11 || native_unwind[1] != 0x0A || native_unwind[2] != 2 || native_unwind[3] != 0)
            throw std::runtime_error("unexpected constructor unwind shape");
        // Keep native stack unwinding, omit its game exception handler. The
        // fake getter owns no native resources and must never invoke cleanup.
        native_unwind[0] = 1;
        const auto relocate_lea = [&](size_t at, uint32_t original_target, int32_t local_target) {
            if (bytes[at] != 0x48 || bytes[at + 1] != 0x8D || bytes[at + 2] != 0x05)
                throw std::runtime_error("unexpected RIP-relative LEA");
            int32_t displacement = 0;
            std::memcpy(&displacement, bytes.data() + at + 3, sizeof displacement);
            if (static_cast<int64_t>(kCtor) + static_cast<int64_t>(at) + 7 + displacement != original_target)
                throw std::runtime_error("unexpected native vtable reference");
            displacement = local_target - static_cast<int32_t>(at + 7);
            std::memcpy(bytes.data() + at + 3, &displacement, sizeof displacement);
        };
        relocate_lea(0x0D, kBaseVtable, 0x1040);
        relocate_lea(0x1B, kTargetVtable, 0x1000);
        std::memcpy(memory_.bytes, bytes.data(), bytes.size());
        std::memcpy(memory_.bytes + 0x100, native_unwind.data(), native_unwind.size());
        DWORD prior = 0;
        if (!VirtualProtect(memory_.bytes, 0x1000, PAGE_EXECUTE_READ, &prior) ||
            !VirtualProtect(memory_.bytes + 0x1000, 0x1000, PAGE_READONLY, &prior) ||
            !FlushInstructionCache(GetCurrentProcess(), memory_.bytes, kCtorSize))
            throw std::runtime_error("cannot protect local replay");
        registered_ = RtlAddFunctionTable(&unwind_, 1, reinterpret_cast<DWORD64>(memory_.bytes)) != FALSE;
        if (!registered_) throw std::runtime_error("cannot register local unwind data");
    }
    ~ConstructorReplay() { if (registered_) RtlDeleteFunctionTable(&unwind_); }
    ConstructorReplay(const ConstructorReplay&) = delete;
    ConstructorReplay& operator=(const ConstructorReplay&) = delete;
};

struct FakeActor { const uintptr_t* vtable; uintptr_t session; uint64_t canary; };
const FakeActor* g_expected_actor = nullptr;
uint32_t g_getter_calls = 0;
bool g_correct_receiver = true;
uintptr_t __fastcall session_getter(FakeActor* actor) {
    ++g_getter_calls;
    g_correct_receiver = g_correct_receiver && actor == g_expected_actor;
    return actor->session;
}

using Constructor = void*(__fastcall*)(void*, FakeActor*);
bool invoke(Constructor fn, void* finder, FakeActor* actor, void** result, DWORD* exception) noexcept {
    __try {
        *result = fn(finder, actor);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *exception = GetExceptionCode();
        return false;
    }
}

template <class T, size_t N>
void put(std::array<uint8_t, N>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof value);
}

void replay_tests(PeReader& pe) {
    ConstructorReplay replay(pe);
    const auto fn = reinterpret_cast<Constructor>(replay.code());
    std::array<uintptr_t, 0xE8 / sizeof(uintptr_t) + 1> vtable{};
    vtable[0xE8 / sizeof(uintptr_t)] = reinterpret_cast<uintptr_t>(&session_getter);
    FakeActor actor{vtable.data(), 0x1234567887654321ull, 0xA17CA17CA17CA17Cull};
    g_expected_actor = &actor;
    for (int scenario = 0; scenario < 3; ++scenario) {
        // Valid session, null actor, then a valid actor with no session. Each
        // fixture starts dirty to catch incomplete initialization and writes
        // outside the exact 24-byte finder (including its untouched padding).
        actor.session = scenario == 2 ? 0 : 0x1234567887654321ull;
        const FakeActor actor_before = actor;
        const auto vtable_before = vtable;
        alignas(16) std::array<uint8_t, 16 + 0x18 + 16> guarded{};
        guarded.fill(0xA5);
        auto expected = guarded;
        put(expected, 16, replay.target_vtable());
        expected[16 + 8] = 0;
        put(expected, 16 + 0x10, scenario == 1 ? uintptr_t{0} : actor.session);
        const uint32_t calls_before = g_getter_calls;
        void* result = nullptr;
        DWORD exception = 0;
        const bool returned = invoke(fn, guarded.data() + 16, scenario == 1 ? nullptr : &actor, &result, &exception);
        CHECK(returned);
        if (!returned) std::printf("constructor replay exception 0x%08lX\n", exception);
        CHECK(result == guarded.data() + 16);
        CHECK(guarded == expected);
        CHECK(g_getter_calls == calls_before + (scenario == 1 ? 0u : 1u));
        CHECK(g_correct_receiver);
        CHECK(actor.vtable == actor_before.vtable && actor.session == actor_before.session && actor.canary == actor_before.canary);
        CHECK(vtable == vtable_before);
    }
    std::printf("native 3527 ToTarget: session getter ABI, null actor, null session, padding and canaries checked\n");
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 1) {
        std::printf("SKIP: native replay needs the installed 3527 executable (--exe PATH)\n");
        return 77;
    }
    if (argc != 3 || std::wstring(argv[1]) != L"--exe") {
        std::printf("usage: cdmp_tests_optd_milestone_native --exe PATH\n");
        return 2;
    }
    try {
        const std::filesystem::path path(argv[2]);
        if (!std::filesystem::exists(path)) {
            std::printf("SKIP: installed 3527 executable is absent\n");
            return 77;
        }
        // 1.0.0.3576 (Steam, 2026-11-06): a new layout; this replay is 3527 / 3549 code and is not ported to it.
        // 1.0.0.3663 (Steam, 2026-11-13): another new layout, the same reason.
        if (const auto size = std::filesystem::file_size(path); size == 326872984 || size == 335440280) {
            std::printf("SKIP: the installed executable is 1.0.0.%s; this replay is 3527 / 3549 code\n",
                        size == 326872984 ? "3576" : "3663");
            return 77;
        }
        PeReader pe(path);
        replay_tests(pe);
    } catch (const std::exception& e) {
        std::printf("FAIL: %s\n", e.what());
        ++g_failures;
    }
    std::printf("optd_milestone_native: %s (%d failures)\n", g_failures ? "FAILED" : "passed", g_failures);
    return g_failures ? 1 : 0;
}
