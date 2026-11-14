// Offline replay of 3527 action-application blend code. No game process is
// opened. Native bytes are read from the pinned installed executable at run
// time; only test-owned fixtures and this process's executable copy are used.
#include <windows.h>
#include <safetyhook.hpp>
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
#include "mod/game/character_phase_ready.h"

namespace {
int g_failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); ++g_failures; } } while (0)
constexpr uint32_t kBlock = 0x25191E0, kBlockSize = 0xB3;
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
constexpr const char* kBlockHash = "ce1c11d0fa09c49694ec683bfef1a99740cc805a8d09f5b668dcebd6b2e0986c";

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

struct Registers { std::array<uintptr_t, 4> before{}, after{}; };
using Apply = void(__fastcall*)(void* cc, void* input, Registers* registers);
float __fastcall blend_value(void* data, uintptr_t unused, void* layer, uint8_t flag);

class ApplyReplay {
    Allocation memory_;
    std::array<RUNTIME_FUNCTION, 2> unwind_{};
    bool registered_ = false;
public:
    // Test-owned adapter: save RBX/RSI/RDI/R15, reserve aligned shadow space,
    // capture incoming nonvolatiles, and pass RCX/RDX as native R15/RSI.
    static constexpr uint8_t prefix[]{
        0x53,0x56,0x57,0x41,0x57,0x48,0x83,0xEC,0x28,
        0x4C,0x89,0x44,0x24,0x20,
        0x49,0x89,0x18,0x49,0x89,0x70,0x08,0x49,0x89,0x78,0x10,0x4D,0x89,0x78,0x18,
        0x4C,0x8B,0xF9,0x48,0x8B,0xF2};
    // Return instead of entering the enclosing game's cleanup at 2519293.
    static constexpr uint8_t suffix[]{
        0x4C,0x8B,0x54,0x24,0x20,0x48,0x83,0xC4,0x28,0x41,0x5F,0x5F,0x5E,0x5B,
        0x49,0x89,0x5A,0x20,0x49,0x89,0x72,0x28,0x49,0x89,0x7A,0x30,0x4D,0x89,0x7A,0x38,0xC3};
    static constexpr uint32_t body_offset = sizeof prefix;
    uint8_t* code() const { return memory_.bytes; }
    uint8_t* site() const { return code() + body_offset + 0x14; }
    uintptr_t resume() const { return reinterpret_cast<uintptr_t>(code() + body_offset + 0x1C); }
    Apply function() const { return reinterpret_cast<Apply>(code()); }
    uint8_t* secondary() const { return code() + 0x800; }
    uint8_t* secondary_site() const { return secondary() + 0x3D; }
    uintptr_t secondary_resume() const { return reinterpret_cast<uintptr_t>(secondary() + 0x45); }
    explicit ApplyReplay(PeReader& pe) {
        const auto enclosing = pe.function(0x2517A80);
        if (enclosing.EndAddress != 0x25198B3) throw std::runtime_error("unexpected ApplyAction boundary");
        auto body = pe.rva(kBlock, kBlockSize);
        if (cdmp::sha256::hex(cdmp::sha256::of(body)) != kBlockHash)
            throw std::runtime_error("native blend block SHA256 mismatch");
        // The true predicate branch calls an isolated copy of the complete
        // native secondary helper. Its only external call becomes our getter.
        int32_t relative = 0;
        std::memcpy(&relative, body.data() + 0x33, sizeof relative);
        if (body[0x32] != 0xE8 || static_cast<int64_t>(kBlock) + 0x37 + relative != 0x251A170)
            throw std::runtime_error("unexpected alternate native call");
        relative = 0x800 - static_cast<int32_t>(body_offset + 0x37);
        std::memcpy(body.data() + 0x33, &relative, sizeof relative);
        std::memcpy(code(), prefix, sizeof prefix);
        std::memcpy(code() + body_offset, body.data(), body.size());
        std::memcpy(code() + body_offset + body.size(), suffix, sizeof suffix);
        constexpr uint8_t unwind[]{1,9,5,0,9,0x42,5,0xF0,3,0x70,2,0x60,1,0x30,0,0};
        std::memcpy(code() + 0x400, unwind, sizeof unwind);
        unwind_[0] = {0, static_cast<DWORD>(sizeof prefix + kBlockSize + sizeof suffix), 0x400};
        const auto second_function = pe.function(0x251A170);
        if (second_function.EndAddress != 0x251A269) throw std::runtime_error("unexpected secondary boundary");
        auto second = pe.rva(0x251A170, 0xF9);
        if (cdmp::sha256::hex(cdmp::sha256::of(second)) !=
            "9d3804cfdc1d2404e2b9549c4a81b98050d7344b6f9bc578101efc28a759ea3c")
            throw std::runtime_error("secondary recipe SHA256 mismatch");
        auto second_unwind = pe.rva(second_function.UnwindData, 28);
        if (second_unwind[0] != 1 || second_unwind[1] != 0x1E || second_unwind[2] != 12 || second_unwind[3] != 0)
            throw std::runtime_error("unexpected secondary unwind shape");
        std::memcpy(&relative, second.data() + 0x99, sizeof relative);
        if (second[0x98] != 0xE8 || 0x251A20Dll + relative != 0x2078C90)
            throw std::runtime_error("unexpected native float getter call");
        relative = 0xB00 - (0x800 + 0x9D);
        std::memcpy(second.data() + 0x99, &relative, sizeof relative);
        std::memcpy(secondary(), second.data(), second.size());
        std::memcpy(code() + 0xA00, second_unwind.data(), second_unwind.size());
        // Test-owned absolute tail jump to the C++ getter; no game function
        // or address remains callable outside the two isolated copies.
        constexpr uint8_t jump[]{0xFF,0x25,0,0,0,0};
        std::memcpy(code() + 0xB00, jump, sizeof jump);
        const uintptr_t getter = reinterpret_cast<uintptr_t>(&blend_value);
        std::memcpy(code() + 0xB06, &getter, sizeof getter);
        unwind_[1] = {0x800, 0x8F9, 0xA00};
        DWORD prior = 0;
        if (!VirtualProtect(code(), 0x2000, PAGE_EXECUTE_READ, &prior) ||
            !FlushInstructionCache(GetCurrentProcess(), code(), 0x2000))
            throw std::runtime_error("cannot protect local replay");
        registered_ = RtlAddFunctionTable(unwind_.data(), static_cast<DWORD>(unwind_.size()), reinterpret_cast<DWORD64>(code())) != FALSE;
        if (!registered_) throw std::runtime_error("cannot register adapter unwind");
    }
    ~ApplyReplay() { if (registered_) RtlDeleteFunctionTable(unwind_.data()); }
    ApplyReplay(const ApplyReplay&) = delete;
    ApplyReplay& operator=(const ApplyReplay&) = delete;
};

template <class T, size_t N> void put(std::array<uint8_t, N>& b, size_t at, T value) {
    std::memcpy(b.data() + at, &value, sizeof value);
}
template <class T, size_t N> T get(const std::array<uint8_t, N>& b, size_t at) {
    T value{}; std::memcpy(&value, b.data() + at, sizeof value); return value;
}
uint32_t g_actor_calls = 0;
bool g_actor_call_ok = true;
uintptr_t g_expected_actor = 0;
bool g_use_secondary = false;
bool __fastcall actor_predicate(void* actor, uint8_t mode) {
    ++g_actor_calls;
    g_actor_call_ok = g_actor_call_ok && reinterpret_cast<uintptr_t>(actor) == g_expected_actor && mode == 5;
    return g_use_secondary;
}
uint32_t g_blend_calls = 0;
bool g_blend_call_ok = true;
uintptr_t g_blend_data = 0;
std::array<uintptr_t, 2> g_blend_layers{};
uint8_t g_blend_flag = 0;
float __fastcall blend_value(void* data, uintptr_t, void* layer, uint8_t flag) {
    ++g_blend_calls;
    const uintptr_t address = reinterpret_cast<uintptr_t>(layer);
    g_blend_call_ok = g_blend_call_ok && reinterpret_cast<uintptr_t>(data) == g_blend_data &&
                      flag == g_blend_flag && (address == g_blend_layers[0] || address == g_blend_layers[1]);
    return address == g_blend_layers[0] ? 0.25f : 0.75f;
}

struct Fixture {
    std::array<uintptr_t, 0x188 / 8 + 1> vtable{};
    std::array<uint8_t, 0x80> actor{};
    std::array<uint8_t, 0x80> components{};
    std::array<uint8_t, 0x60> appearance{};
    std::array<uint8_t, 0x40> properties{};
    std::array<uint8_t, 0xA0> cc{};
    std::array<uint8_t, 0x20> selector{};
    std::array<uint8_t, 0x100> input{};
    std::array<std::array<uint8_t, 0x130>, 2> layer{};
    std::array<std::array<uint8_t, 0x120>, 2> current{};
    std::array<std::array<uint8_t, 0x38>, 2> playback{};
    std::array<std::array<uint8_t, 0x88>, 2> resource{};
    Fixture() {
        vtable[0x188 / 8] = reinterpret_cast<uintptr_t>(&actor_predicate);
        actor.fill(0xA5); cc.fill(0xA5); selector.fill(0xA5); input.fill(0xA5);
        put(actor, 0, reinterpret_cast<uintptr_t>(vtable.data()));
        put(actor, 0x68, reinterpret_cast<uintptr_t>(components.data()));
        put(components, 0x58, reinterpret_cast<uintptr_t>(appearance.data()));
        put(appearance, 0x48, reinterpret_cast<uintptr_t>(properties.data()));
        put(cc, 8, reinterpret_cast<uintptr_t>(actor.data()));
        put(cc, 0x30, reinterpret_cast<uintptr_t>(selector.data()));
        put(cc, 0x58, reinterpret_cast<uintptr_t>(input.data()));
        selector[0x1B] = 0;
        put(input, 0x70, 0.25f); put(input, 0xE8, 0.75f);
        for (size_t i = 0; i != 2; ++i) {
            layer[i].fill(0xA5); current[i].fill(0xA5); playback[i].fill(0xA5); resource[i].fill(0xA5);
            put(cc, 0x88 + i * 8, reinterpret_cast<uintptr_t>(layer[i].data()));
            put(layer[i], 0, uintptr_t{1}); put(layer[i], 8, uintptr_t{2});
            put(layer[i], 0x10, reinterpret_cast<uintptr_t>(current[i].data()));
            put(layer[i], 0x18, reinterpret_cast<uintptr_t>(playback[i].data()));
            current[i][0x111] = 1;
            put(playback[i], 0x28, reinterpret_cast<uintptr_t>(resource[i].data()));
            resource[i][0x7E] = 0;
            put(layer[i], 0x110, -3.0f); put(layer[i], 0x114, -4.0f);
        }
    }
    void present(size_t index, bool value) {
        put(layer[index], 0x18, value ? reinterpret_cast<uintptr_t>(playback[index].data()) : uintptr_t{0});
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
};

struct Fault { DWORD code = 0; uintptr_t pc = 0, address = 0; ULONG_PTR access = 0; };
int capture_fault(EXCEPTION_POINTERS* ep, Fault* fault) {
    const auto* e = ep->ExceptionRecord;
    fault->code = e->ExceptionCode;
    fault->pc = reinterpret_cast<uintptr_t>(e->ExceptionAddress);
    if (e->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && e->NumberParameters >= 2) {
        fault->access = e->ExceptionInformation[0]; fault->address = e->ExceptionInformation[1];
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
bool invoke(Apply fn, Fixture* f, Registers* registers, Fault* fault) {
    __try { fn(f->cc.data(), f->input.data(), registers); return true; }
    __except (capture_fault(GetExceptionInformation(), fault)) { return false; }
}

uintptr_t g_resume = 0, g_expected_cc = 0, g_expected_input = 0;
uintptr_t g_secondary_resume = 0;
bool g_eligible = true;
uint32_t g_hook_hits = 0, g_skipped = 0;
uint32_t g_secondary_hits = 0, g_secondary_skipped = 0;
void on_flag(SafetyHookContext& ctx) {
    ++g_hook_hits;
    CHECK(ctx.r15 == g_expected_cc && ctx.rsi == g_expected_input);
    auto expected = ctx;
    const bool skip = cdmp::game::phase3527::skip_null_playback_flag(ctx, g_resume, g_eligible);
    if (skip) { ++g_skipped; expected.rdi = 0; expected.rip = g_resume; }
    CHECK(std::memcmp(&ctx, &expected, sizeof ctx) == 0);
}
void on_secondary_flag(SafetyHookContext& ctx) {
    ++g_secondary_hits;
    CHECK(ctx.r14 == g_expected_cc);
    auto expected = ctx;
    const bool skip = cdmp::game::phase3527::skip_null_playback_secondary(ctx, g_secondary_resume, g_eligible);
    if (skip) { ++g_secondary_skipped; expected.rbp = 0; expected.rip = g_secondary_resume; }
    CHECK(std::memcmp(&ctx, &expected, sizeof ctx) == 0);
}

bool run(ApplyReplay& replay, Fixture& f) {
    g_expected_actor = reinterpret_cast<uintptr_t>(f.actor.data());
    g_expected_cc = reinterpret_cast<uintptr_t>(f.cc.data());
    g_expected_input = reinterpret_cast<uintptr_t>(f.input.data());
    g_blend_data = g_expected_input;
    g_blend_layers = {reinterpret_cast<uintptr_t>(f.layer[0].data()), reinterpret_cast<uintptr_t>(f.layer[1].data())};
    g_blend_flag = static_cast<uint8_t>((get<uint32_t>(f.properties, 0x34) >> 19) & 1);
    const auto actor = f.actor;
    const auto cc = f.cc;
    const auto selector = f.selector;
    const auto input = f.input;
    const auto current = f.current;
    const auto playback = f.playback;
    const auto resource = f.resource;
    const auto components = f.components;
    const auto appearance = f.appearance;
    const auto properties = f.properties;
    const auto before = f.layer;
    Registers registers{};
    Fault fault;
    const uint32_t calls = g_actor_calls;
    const uint32_t blend_calls = g_blend_calls;
    const bool ok = invoke(replay.function(), &f, &registers, &fault);
    CHECK(ok && fault.code == 0);
    CHECK(registers.before == registers.after);
    CHECK(g_actor_calls == calls + 1 && g_actor_call_ok);
    CHECK(f.actor == actor && f.cc == cc && f.selector == selector && f.input == input);
    CHECK(f.current == current && f.playback == playback && f.resource == resource);
    CHECK(f.components == components && f.appearance == appearance && f.properties == properties);
    const uint32_t ready = (get<uintptr_t>(before[0], 0x18) ? 1u : 0u) + (get<uintptr_t>(before[1], 0x18) ? 1u : 0u);
    CHECK(g_blend_calls == blend_calls + (g_use_secondary ? ready : 0u) && g_blend_call_ok);
    for (size_t i = 0; i != 2; ++i) {
        auto expected = before[i];
        if (get<uintptr_t>(before[i], 0x18)) {
            const bool selected_flag = i == f.selector[0x1B] && f.resource[i][0x7E] != 0;
            put(expected, 0x110, selected_flag ? 1.0f : get<float>(f.input, 0x70 + i * 0x78));
            put(expected, 0x114, selected_flag ? get<float>(f.input, 0x70 + i * 0x78) : 1.0f);
        }
        CHECK(f.layer[i] == expected);
    }
    if (!ok) std::printf("blend replay exception 0x%08lX\n", fault.code);
    return ok;
}

void helper_tests() {
    SafetyHookContext ctx{};
    ctx.rcx = 0; ctx.rdi = 0xABCD; ctx.rip = 0x1234; ctx.r15 = 0x7654;
    const auto before = ctx;
    CHECK(!cdmp::game::phase3527::skip_null_playback_flag(ctx, 0x9876, false));
    CHECK(std::memcmp(&ctx, &before, sizeof ctx) == 0);
    CHECK(!cdmp::game::phase3527::skip_null_playback_flag(ctx, 0, true));
    CHECK(std::memcmp(&ctx, &before, sizeof ctx) == 0);
    CHECK(!cdmp::game::phase3527::skip_null_playback_secondary(ctx, 0x9876, false));
    CHECK(std::memcmp(&ctx, &before, sizeof ctx) == 0);
    CHECK(!cdmp::game::phase3527::skip_null_playback_secondary(ctx, 0, true));
    CHECK(std::memcmp(&ctx, &before, sizeof ctx) == 0);
}

void native_tests(PeReader& pe) {
    ApplyReplay replay(pe);
    Fixture broken;
    broken.present(0, false);
    Registers registers{};
    Fault fault;
    CHECK(!invoke(replay.function(), &broken, &registers, &fault));
    CHECK(fault.code == EXCEPTION_ACCESS_VIOLATION && fault.access == 0 && fault.address == 0x28);
    CHECK(fault.pc == reinterpret_cast<uintptr_t>(replay.site()));
    fault = {};
    CHECK(!invoke(reinterpret_cast<Apply>(replay.secondary()), &broken, &registers, &fault));
    CHECK(fault.code == EXCEPTION_ACCESS_VIOLATION && fault.access == 0 && fault.address == 0x28);
    CHECK(fault.pc == reinterpret_cast<uintptr_t>(replay.secondary_site()));
    g_resume = replay.resume();
    g_secondary_resume = replay.secondary_resume();
    auto hook = safetyhook::create_mid(replay.site(), &on_flag);
    auto secondary_hook = safetyhook::create_mid(replay.secondary_site(), &on_secondary_flag);
    CHECK(static_cast<bool>(hook));
    CHECK(static_cast<bool>(secondary_hook));
    if (!hook || !secondary_hook) return;
    CHECK(hook.original_bytes().size() == 8);
    CHECK(secondary_hook.original_bytes().size() == 8);
    for (const bool secondary : {false, true}) {
      g_use_secondary = secondary;
    for (uint8_t selected = 0; selected != 2; ++selected) {
        for (uint8_t flag = 0; flag != 2; ++flag) {
            Fixture valid;
            valid.selector[0x1B] = selected;
            valid.resource[selected][0x7E] = flag;
            put(valid.properties, 0x34, static_cast<uint32_t>(flag) << 19);
            const auto dirty = valid.layer;
            CHECK(static_cast<bool>(hook.disable()));
            CHECK(static_cast<bool>(secondary_hook.disable()));
            CHECK(run(replay, valid));
            const auto original = valid.layer;
            valid.layer = dirty;
            CHECK(static_cast<bool>(hook.enable()));
            CHECK(static_cast<bool>(secondary_hook.enable()));
            const uint32_t skips = g_skipped;
            CHECK(run(replay, valid));
            CHECK(valid.layer == original && g_skipped == skips);
        }
        Fixture missing;
        missing.selector[0x1B] = selected;
        put(missing.properties, 0x34, static_cast<uint32_t>(selected) << 19);
        missing.present(selected, false);
        uint32_t skips = g_skipped;
        CHECK(run(replay, missing));
        CHECK(g_skipped == skips + 1);
        missing.present(1 - selected, false);
        skips = g_skipped;
        CHECK(run(replay, missing));
        CHECK(g_skipped == skips + 1);
        missing.present(selected, true);
        missing.resource[selected][0x7E] = 1;
        skips = g_skipped;
        CHECK(run(replay, missing));
        CHECK(g_skipped == skips);
    }
    }
    CHECK(g_hook_hits == 20 && g_skipped == 8);
    CHECK(g_secondary_hits == 10 && g_secondary_skipped == 4);
    std::printf("native 3527 blend replay: two original null+0x28 AVs; exact 8-byte midhooks; both vf188 paths; "
                "both selections; other-layer updates; valid flags unchanged; null/recovery; register and object canaries\n");
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 1) { std::printf("SKIP: native replay needs --exe PATH\n"); return 77; }
    if (argc != 3 || std::wstring(argv[1]) != L"--exe") {
        std::printf("usage: cdmp_tests_optd_apply_playback --exe PATH\n"); return 2;
    }
    try {
        helper_tests();
        const std::filesystem::path path(argv[2]);
        if (!std::filesystem::exists(path)) { std::printf("SKIP: installed 3527 executable is absent\n"); return 77; }
        // 1.0.0.3576 (Steam, 2026-11-06): a new layout; this replay is 3527 / 3549 code and is not ported to it.
        // 1.0.0.3663 (Steam, 2026-11-13): another new layout, the same reason.
        if (const auto size = std::filesystem::file_size(path); size == 326872984 || size == 335440280) {
            std::printf("SKIP: the installed executable is 1.0.0.%s; this replay is 3527 / 3549 code\n",
                        size == 326872984 ? "3576" : "3663");
            return 77;
        }
        PeReader pe(path);
        native_tests(pe);
    } catch (const std::exception& e) { std::printf("FAIL: %s\n", e.what()); ++g_failures; }
    std::printf("optd_apply_playback: %s (%d failures)\n", g_failures ? "FAILED" : "passed", g_failures);
    return g_failures ? 1 : 0;
}

