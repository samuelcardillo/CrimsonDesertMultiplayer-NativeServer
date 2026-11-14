#include "mod/session2/guest_save_host.h"

#include <windows.h>

#include <bcrypt.h>
#include <intrin.h>

#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/game_fault.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/host_save_export.h"
#include "mod/session2/identity_probe.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/profile_s2.h"
#include "mod/session2/save_hooks.h"
#include "mod/session2/server.h"

#pragma comment(lib, "bcrypt.lib")
#pragma intrinsic(_ReturnAddress)

namespace cdmp::session2 {
namespace {

using gsv::Action;
using gsv::FileKind;
using gsv::Mode;
using gsv::Owner;

// ---------------------------------------------------------------- build 1.0.0.2976

// Entries (all in .rsrc, inline hooks at the entry only), decoded with capstone over the disk exe (PE 0x6AB28F00).
constexpr uintptr_t kLoadSlot = 0x186F570;  // LoadSlot(mgr, int* res, u32 slot, actor) -> res
constexpr uint8_t kLoadSlotHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89,
                                     0x7C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x55, 0x41, 0x54, 0x41,
                                     0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x50, 0xFF, 0xFF,
                                     0xFF, 0x48, 0x81, 0xEC, 0xB0, 0x01, 0x00, 0x00, 0x4D, 0x8B, 0xF9};
constexpr uintptr_t kSave = 0x186E450;  // SavePlayerToSlot(mgr, int* res, u32 slot, character, opts*) -> res
constexpr uint8_t kSaveHead[] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89,
                                 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57,
                                 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24,
                                 0x78, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x88, 0x02, 0x00, 0x00};
// FlushPendingSaveData(mgr, int* res, character, u16, u8* opts, int* slot_out) -> res (probe only).
constexpr uintptr_t kFlush = 0x1871930;
constexpr uint8_t kFlushHead[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57,
                                  0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x40, 0xFF,
                                  0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC0, 0x01, 0x00, 0x00, 0x45, 0x0F, 0xB7,
                                  0xF9, 0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xF2};
// Called (never hooked): GetOrCreateSlot's .rsrc thunk (jmp .xtls 0xEF537A0) and AddFile.
constexpr uintptr_t kGetOrCreate = 0x2355EC0;  // (S, const char* name, u8 in_memory) -> slot
constexpr uint8_t kGetOrCreateHead[] = {0xE9, 0xDB, 0xD8, 0xBF, 0x0C};
constexpr uintptr_t kAddFile = 0x235B100;  // (slot, const char* name) -> ...; makes the 0x140-byte file object
constexpr uint8_t kAddFileHead[] = {0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
                                    0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xEA, 0x4C, 0x8B, 0xF9};

// The callers (E8 rel32) the decisions tell apart by return address (gsv::k Ret*), and the error codes the game
// itself returns there (u32 globals read with mov eax,[rip+..] at the given site).
struct CallSite {
    uintptr_t at, target;
};
constexpr CallSite kCallSites[] = {
    {0x2C17881, kLoadSlot}, {0x2C3E1CE, kLoadSlot}, {0x1042ABF3, kLoadSlot},  // UserLogin, 3093 lobby, 3093 character
    {0xCBD86CE, kSave},     {0x103BE99A, kSave},                              // autosave, 2910
    {0x28F273A, kFlush},    {0x108393C8, kFlush},                             // logout phase, flush timer
};
struct ErrorSite {
    uintptr_t at, global;
    const char* what;
};
constexpr ErrorSite kErrBusy = {0x186F6DF, 0x6CF7CA4, "LoadSlot's busy error"};
constexpr ErrorSite kErrInvalidSlot = {0x186F62C, 0x6CF7900, "LoadSlot's invalid-slot error"};
constexpr ErrorSite kErrAbsentSlot = {0x2069615, 0x6CF781C, "LoadComponentsFromFile's absent-slot error"};
constexpr ErrorSite kErrSaveFail = {0x186E780, 0x6CF7CA0, "SavePlayerToSlot's own failure"};

// ---------------------------------------------------------------- build 1.0.0.3527
//
// [V capstone, 2026-11-05] The same functions: each entry's only callers are the same ones as in 2976, SavePlayerToSlot
// still reads the character's user at r14 (r9) + 0xA0 (0x19AF82B), and the heads differ only in the frame sizes.
constexpr uint8_t kLoadSlotHead3527[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x44,
    0x89, 0x44, 0x24, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC,
    0x24, 0x50, 0xFF, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xB0, 0x01, 0x00, 0x00, 0x4D, 0x8B, 0xF1};
constexpr uint8_t kSaveHead3527[] = {
    0x4C, 0x89, 0x4C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x48,
    0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8D, 0xAC, 0x24, 0x38, 0xFC, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC8, 0x04, 0x00, 0x00};
constexpr uint8_t kFlushHead3527[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x40, 0xFF, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC0, 0x01, 0x00,
    0x00, 0x45, 0x0F, 0xB7, 0xF9, 0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xF2};
constexpr uint8_t kGetOrCreateHead3527[] = {
    0xE9, 0xEB, 0x5E, 0xEF, 0x0A};
constexpr uint8_t kAddFileHead3527[] = {
    0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC,
    0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xEA, 0x4C, 0x8B, 0xF9};
constexpr CallSite kCallSites3527[] = {
    {0x2EBB21B, 0x19B09D0}, {0x2EE1F31, 0x19B09D0}, {0xE48A09E, 0x19B09D0},
    {0xB744234, 0x19AF6D0}, {0xE42468A, 0x19AF6D0},
    {0x2B5C0FA, 0x19B3020}, {0xE7C0988, 0x19B3020},
};
// 1.0.0.3549: GetOrCreate's thunk now jumps to 0xD33BA90; the callers in the protected section moved (kRets3549).
constexpr uint8_t kGetOrCreateHead3549[] = {
    0xE9, 0x4B, 0x2C, 0xDF, 0x0A};
constexpr CallSite kCallSites3549[] = {
    {0x2EBB21B, 0x19B09D0}, {0x2EE1F31, 0x19B09D0}, {0xE3CCACF, 0x19B09D0},
    {0xB7F1385, 0x19AF6D0}, {0xE37C231, 0x19AF6D0},
    {0x2B5C0FA, 0x19B3020}, {0xE6FC3C8, 0x19B3020},
};
constexpr ErrorSite kErrBusy3527 = {0x19B0B5E, 0x7149DF4, "LoadSlot's busy error"};
constexpr ErrorSite kErrInvalidSlot3527 = {0x19B0AAF, 0x7149A24, "LoadSlot's invalid-slot error"};
constexpr ErrorSite kErrAbsentSlot3527 = {0x222606F, 0x7149940, "LoadComponentsFromFile's absent-slot error"};
constexpr ErrorSite kErrSaveFail3527 = {0x19AF9CA, 0x7149DF0, "SavePlayerToSlot's own failure"};

// ---------------------------------------------------------------- build 1.0.0.3576
//
// [static, 2026-11-06; not yet run] Every head above is byte-identical and unique in the file: LoadSlot 0x19B1610,
// SavePlayerToSlot 0x19B0310 and FlushPendingSaveData 0x19B3C60 (3527's +0xC40), AddFile 0x254F0A0 (+0xDD0), each a
// .pdata entry. GetOrCreateSlot's thunk at 3527's +0xDD0 (0x2549C10, right after the function ending at 0x2549C0E)
// jumps to 0xD372720, which takes (S, name, u8 in_memory) and writes [slot+0x699] = 1; SavePlayerToSlot calls it at
// 0x19B0466, just before it reads the character's user at r14 + 0xA0 (0x19B046B). Callers (E8 scan of every code
// section, the protected one included): exactly 3 of LoadSlot, 2 of SavePlayerToSlot, 2 of FlushPendingSaveData, as
// in 3527. The plain-code ones at 3527's +0xC70; the protected ones: the 3093 character load 0xE3927BF, the autosave
// 0xB8A786C in 0xB8A7670 (the target of the jmp at 0x19B0050 = 3527's 0x19AF410 +0xC40), the 2910 save 0xE35801A in
// 0xE357F60 (the jmp at 0x2B67A70 = 3527's 0x2B66E00 +0xC70) and the flush timer 0xE69FA88. The error sites at the same
// offsets in the moved functions, mov eax,[rip+..] to the error globals moved by +0x2120. The server realm's TLS byte
// is +0x1EB (GetCurrentFieldTime 0x22A9C10: mov edx,0x1EB ; gs:[0x58] ; movzx eax,byte [rdx+rcx]).
// GetOrCreateSlot's thunk: jmp to its 3576 body in the protected section (above).
constexpr uint8_t kGetOrCreateHead3576[] = {0xE9, 0x0B, 0x8B, 0xE2, 0x0A};
constexpr CallSite kCallSites3576[] = {
    {0x2EBBE8B, 0x19B1610}, {0x2EE2BA1, 0x19B1610}, {0xE3927BF, 0x19B1610},
    {0xB8A786C, 0x19B0310}, {0xE35801A, 0x19B0310},
    {0x2B5CD6A, 0x19B3C60}, {0xE69FA88, 0x19B3C60},
};
constexpr ErrorSite kErrBusy3576 = {0x19B179E, 0x714BF14, "LoadSlot's busy error"};
constexpr ErrorSite kErrInvalidSlot3576 = {0x19B16EF, 0x714BB44, "LoadSlot's invalid-slot error"};
constexpr ErrorSite kErrAbsentSlot3576 = {0x2226CAF, 0x714BA60, "LoadComponentsFromFile's absent-slot error"};
constexpr ErrorSite kErrSaveFail3576 = {0x19B060A, 0x714BF10, "SavePlayerToSlot's own failure"};
// The return addresses of the callers above (gsv::CallerRets: user login, 3093 lobby, 3093 character, autosave, 2910,
// logout flush, flush timer).
constexpr gsv::CallerRets kRets3576{0x2EBBE90, 0x2EE2BA6, 0xE3927C4, 0xB8A7871, 0xE35801F, 0x2B5CD6F, 0xE69FA8D};

// ---------------------------------------------------------------- build 1.0.0.3663
//
// [static, 2026-11-13; never run] Every head above is byte-identical and unique in the code section, each a .pdata
// entry: LoadSlot 0x1A16C40 (3576 +0x65630), SavePlayerToSlot 0x1A15930 (+0x65620), FlushPendingSaveData 0x1A192D0
// (+0x65670), AddFile 0x25C0900 (+0x71860). GetOrCreateSlot's thunk 0x25BB470 (AddFile - 0x5490, as in 3576; right
// after the function ending at 0x25BB46F) jumps to 0xD85F010, which writes [slot+0x699] = 1 (0xD85F12E);
// SavePlayerToSlot calls it at 0x1A15A86, just before it reads the character's user at r14 + 0xA0 (0x1A15A8B), as in
// 3576. Callers (E8 scan of every executable section, the protected one included): exactly 3 of LoadSlot, 2 of
// SavePlayerToSlot, 2 of FlushPendingSaveData, as in 3527/3576. Plain code: the user login 0x2F242AB and the 3093 lobby
// 0x2F4B021 (3576 +0x68420 / +0x68480, in that order), the logout flush 0x2BC2A6A (+0x65D00). Protected: the 3093
// character load 0xE9F5065 (in 0xE9F4F70, the jmp at 0x2C172E0 next to the login phases), the autosave 0xBB0BEC8 (in
// 0xBB0BCC0, the target of the jmp at 0x1A15670 = SavePlayerToSlot - 0x2C0, as 3576's 0x19B0050), the 2910 save
// 0xE98E356 (in 0xE98E290, the jmp at 0x2BCD7E0 = 3576's 0x2B67A70 +0x65D70) and the flush timer 0xED099C8 (in
// 0xED09970, the jmp at 0x2F41D90). The error sites at the same offsets in the moved functions (LoadSlot +0x18E / +0xDF,
// LoadComponentsFromFile 0x22951B0 +0xE1F, SavePlayerToSlot +0x2FA), each still mov eax,[rip+..] to the error globals,
// all moved by +0x84DE8. The server realm's TLS byte is +0x1EB (GetCurrentFieldTime 0x231A1E4: mov edx,0x1EB ;
// gs:[0x58] ; movzx eax,byte [rdx+rcx]). FlushPendingSaveData still reads the manager's +0x5C (0x1A193D4).
constexpr uint8_t kGetOrCreateHead3663[] = {0xE9, 0x9B, 0x3B, 0x2A, 0x0B};
constexpr CallSite kCallSites3663[] = {
    {0x2F242AB, 0x1A16C40}, {0x2F4B021, 0x1A16C40}, {0xE9F5065, 0x1A16C40},
    {0xBB0BEC8, 0x1A15930}, {0xE98E356, 0x1A15930},
    {0x2BC2A6A, 0x1A192D0}, {0xED099C8, 0x1A192D0},
};
constexpr ErrorSite kErrBusy3663 = {0x1A16DCE, 0x71D0CFC, "LoadSlot's busy error"};
constexpr ErrorSite kErrInvalidSlot3663 = {0x1A16D1F, 0x71D092C, "LoadSlot's invalid-slot error"};
constexpr ErrorSite kErrAbsentSlot3663 = {0x2295FCF, 0x71D0848, "LoadComponentsFromFile's absent-slot error"};
constexpr ErrorSite kErrSaveFail3663 = {0x1A15C2A, 0x71D0CF8, "SavePlayerToSlot's own failure"};
// The return addresses of the callers above (each call + 5), in gsv::CallerRets' order.
constexpr gsv::CallerRets kRets3663{0x2F242B0, 0x2F4B026, 0xE9F506A, 0xBB0BECD, 0xE98E35B, 0x2BC2A6F, 0xED099CD};

struct Addrs {
    uintptr_t load_slot, save, flush, get_or_create, add_file;
    std::span<const uint8_t> load_head, save_head, flush_head, get_or_create_head, add_file_head;
    std::span<const CallSite> call_sites;
    const ErrorSite* err_busy;
    const ErrorSite* err_invalid;
    const ErrorSite* err_absent;
    const ErrorSite* err_save;
    gsv::CallerRets rets;
    uint32_t tls_realm;
};
const Addrs kAddrs2976{kLoadSlot, kSave, kFlush, kGetOrCreate, kAddFile,
                       kLoadSlotHead, kSaveHead, kFlushHead, kGetOrCreateHead, kAddFileHead,
                       kCallSites, &kErrBusy, &kErrInvalidSlot, &kErrAbsentSlot, &kErrSaveFail, gsv::kRets2976, 0x1EC};
const Addrs kAddrs3527{0x19B09D0, 0x19AF6D0, 0x19B3020, 0x2548E40, 0x254E2D0,
                       kLoadSlotHead3527, kSaveHead3527, kFlushHead3527, kGetOrCreateHead3527, kAddFileHead3527,
                       kCallSites3527, &kErrBusy3527, &kErrInvalidSlot3527, &kErrAbsentSlot3527, &kErrSaveFail3527,
                       gsv::kRets3527, 0x1EB};
const Addrs kAddrs3549{0x19B09D0, 0x19AF6D0, 0x19B3020, 0x2548E40, 0x254E2D0,
                       kLoadSlotHead3527, kSaveHead3527, kFlushHead3527, kGetOrCreateHead3549, kAddFileHead3527,
                       kCallSites3549, &kErrBusy3527, &kErrInvalidSlot3527, &kErrAbsentSlot3527, &kErrSaveFail3527,
                       gsv::kRets3549, 0x1EB};
const Addrs kAddrs3576{0x19B1610, 0x19B0310, 0x19B3C60, 0x2549C10, 0x254F0A0,
                       kLoadSlotHead3527, kSaveHead3527, kFlushHead3527, kGetOrCreateHead3576, kAddFileHead3527,
                       kCallSites3576, &kErrBusy3576, &kErrInvalidSlot3576, &kErrAbsentSlot3576, &kErrSaveFail3576,
                       kRets3576, 0x1EB};
const Addrs kAddrs3663{0x1A16C40, 0x1A15930, 0x1A192D0, 0x25BB470, 0x25C0900,
                       kLoadSlotHead3527, kSaveHead3527, kFlushHead3527, kGetOrCreateHead3663, kAddFileHead3527,
                       kCallSites3663, &kErrBusy3663, &kErrInvalidSlot3663, &kErrAbsentSlot3663, &kErrSaveFail3663,
                       kRets3663, 0x1EB};
const Addrs& addrs() {
    if (game::is_3549()) return kAddrs3549;
    if (game::is_3576()) return kAddrs3576;
    if (game::is_3663()) return kAddrs3663;
    return game::current_build() == game::Build::v3527 ? kAddrs3527 : kAddrs2976;
}

// Fields (evidence in the report and in guest_save_logic.h).
constexpr uint32_t kSlotMemoryOnly = 0x699;  // u8: GetOrCreateSlot .xtls 0xEF538D7, CommitSlot .xtls 0xEF5186D
constexpr uint32_t kSlotInMemory = 0x69C;    // u8: CreateSlot 0x2355BB0's last argument
constexpr uint32_t kFileHeader = 0x98;       // the file's 0x80-byte header (0x2357DA0 copies it at each read)
constexpr uint32_t kActorDescriptor = 0x88;  // actor -> descriptor; byte +1 == 0: "lobby" (0x20688A0)
constexpr uint32_t kActorUser = 0xA0;        // character -> ServerUserActor (0x186E5DD; .xtls 0x1042AB16)
constexpr uint32_t kActorKey = 0x60;         // u32 actor key (identity_fix.h idf::kActorKey)
constexpr uint32_t kMgrPendingSlot = 0x5C;   // i32: the slot a deferred autosave left (FlushPendingSaveData)

using LoadSlotFn = int* (*)(uintptr_t, int*, uint32_t, uintptr_t);
using GetOrCreateFn = uintptr_t (*)(uintptr_t, const char*, uint8_t);
using AddFileFn = uintptr_t (*)(uintptr_t, const char*);

// ---------------------------------------------------------------- state

// The slot's state as bits, so the hooks read it without a lock (gsv::SlotState is the decoded form).
enum : uint32_t { kStaged = 1, kLive = 2, kDisabled = 4, kPoisoned = 8, kLobbyOk = 16, kSaveOk = 32 };

uintptr_t g_base = 0;
std::atomic<Mode> g_mode{Mode::Off};
std::atomic<uint32_t> g_bits{0};
int32_t g_err_busy = 0, g_err_invalid = 0, g_err_absent = 0, g_err_save = 0;  // set at install, then read only
GetOrCreateFn g_get_or_create = nullptr;
AddFileFn g_add_file = nullptr;
SafetyHookInline g_h_load_slot, g_h_save, g_h_flush;
std::atomic<GuestSaveResultFn> g_result_fn{nullptr};

// Set at install, then read only: <sandbox>\<account> and its slot204 (the folder the game reads); the staging
// folder <...\CD>\cdmp_guest_save_staging\<account> with slot204.incoming and slot204.old, a sibling of the save
// folder and of the sandbox (same volume: the moves are renames), outside every folder the game lists (it lists the
// account folder at each load and save: review item 5); the mailbox.
std::wstring g_account_dir, g_slot_dir, g_staging_dir, g_incoming, g_old_dir, g_mailbox_root;
std::atomic<uintptr_t> g_verified_user{0};  // the user actor whose lobby was verified (its login's save is user 2's)
char g_slot_name[16] = {};  // "slot204"

std::mutex g_mu;  // the folder moves (phase B's thread vs the server thread) and the guest id
std::string g_guest_id = "unknown";
// Phase B, under g_mu: the labels (guest, slot N, line, base) of the staged files and of the live slot (the staged
// pair becomes the live one when it moves in). The exports carry the live one.
GuestSaveLabel g_staged_label, g_live_label;
std::atomic<uint32_t> g_gen_floor{0};   // phase B: the next generation is above this (the guest's base / acknowledged)
std::atomic<uint32_t> g_last_error{0};  // the last game error on user 2's loads / saves (SAVE_STATUS)

std::atomic<uint64_t> c_load_calls{0}, c_load_user2{0}, c_load_remapped{0}, c_load_refused{0};
std::atomic<uint64_t> c_save_calls{0}, c_save_user2{0}, c_save_remapped{0}, c_save_refused{0};
std::atomic<uint64_t> c_exported{0}, c_export_failed{0}, c_flush_calls{0}, c_flush_user2{0};
std::atomic<uint64_t> c_moved_in{0}, c_slot_made{0}, c_files_added{0}, c_verified{0};
std::atomic<uint32_t> g_last_gen{0};

// Line budgets: per point, and the host's lines (comparison) per point.
class Budget {
public:
    constexpr Budget(uint32_t cap, uint32_t host_cap) : cap_(cap), host_cap_(host_cap) {}
    bool take(bool is_host) {
        if (is_host && host_.fetch_add(1, std::memory_order_relaxed) >= host_cap_) return false;
        return lines_.fetch_add(1, std::memory_order_relaxed) < cap_;
    }

private:
    std::atomic<uint32_t> lines_{0}, host_{0};
    uint32_t cap_, host_cap_;
};
Budget g_lines_load{150, 30}, g_lines_save{150, 30}, g_lines_flush{60, 20}, g_lines_phase{100, 100};

gsv::SlotState decode(uint32_t b) {
    gsv::SlotState s;
    s.staged = (b & kStaged) != 0;
    s.live = (b & kLive) != 0;
    s.disabled = (b & kDisabled) != 0;
    s.poisoned = (b & kPoisoned) != 0;
    s.lobby_ok = (b & kLobbyOk) != 0;
    s.save_ok = (b & kSaveOk) != 0;
    return s;
}
gsv::SlotState state_now() { return decode(g_bits.load(std::memory_order_acquire)); }
void set_bits(uint32_t on) { g_bits.fetch_or(on, std::memory_order_acq_rel); }
void clear_bits(uint32_t off) { g_bits.fetch_and(~off, std::memory_order_acq_rel); }
void drop_verification(const gsv::VerifyDrop& d) {
    if (d.lobby) g_verified_user.store(0);
    clear_bits((d.lobby ? kLobbyOk : 0u) | (d.save ? kSaveOk : 0u));
}

std::string state_text(const gsv::SlotState& s) {
    std::string t;
    if (s.staged) t += "staged ";
    if (s.live) t += "live ";
    if (s.lobby_ok) t += "lobby-ok ";
    if (s.save_ok) t += "save-ok ";
    if (s.disabled) t += "DISABLED ";
    if (s.poisoned) t += "POISONED ";
    if (t.empty()) return "empty";
    t.pop_back();
    return t;
}

// ---------------------------------------------------------------- small helpers

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}
uintptr_t peekp(uintptr_t a) {
    uintptr_t v = 0;
    return peek(a, v) ? v : 0;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}
std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string rva_text(uint64_t rva) { return std::format("exe+0x{:X}", rva); }
uint64_t rva_of(const void* p) {
    const auto a = reinterpret_cast<uintptr_t>(p);
    return a >= g_base ? a - g_base : a;
}

// The server's realm, by the game's TLS byte (+0x1EC of TLS block 0, set by ServerRunThread 0x27733A6): as
// identity_fix.cpp's on_server_thread (the loads run on the server's handler threads, not server_thread_id()).
bool on_server_thread() {
    const uintptr_t tls_array = static_cast<uintptr_t>(__readgsqword(0x58));
    uintptr_t block = 0;
    uint8_t flag = 0;
    return game::safe_read(tls_array, &block, sizeof block) && block &&
           game::safe_read(block + addrs().tls_realm, &flag, sizeof flag) && flag != 0;
}

std::string thread_text() {
    return std::format("tid {} ({})", GetCurrentThreadId(), on_server_thread() ? "server realm" : "NOT the server's");
}

// Whose user, from positive facts (gsv::classify_owner; review of phase A, items 1, 6 and 7): `user` against the
// validated user 2 and host, and its own session back pointer (+0x1F8) against the game's session (ServerNet+0x18)
// and the mod's session 2 of every epoch; `character` (0 for a user actor) by its key against user 2's character
// key of this epoch. Reads only; any thread. `facts` (P8 S35 phase E, host_save_export.h): the facts themselves,
// for the journal's positive identity (hsv::positive_host).
Owner owner_of_user(uintptr_t user, uintptr_t character = 0, gsv::UserFacts* facts = nullptr) {
    gsv::UserFacts f;
    uintptr_t u2 = 0, host = 0;
    f.is_user2 = user && server_user2(u2) && user == u2;
    f.is_host = user && server_host_user(host) && user == host;
    for (uint32_t e = 0; e < kMaxGuestEpochs; ++e) {
        if (server_epoch_session(e)) f.any_guest_session = true;
    }
    uintptr_t vt = 0, session = 0, net = 0, game_session = 0;
    if (user && peek(user, vt) && vt == g_base + profile::rva(off::kServerUserActorVtable) && peek(user + off::kUser_Session, session) &&
        session) {
        f.session_known = true;
        f.session_is_host = peek(g_base + profile::rva(off::kServerNetSlot), net) && peek(net + off::kServerNet_Session, game_session) &&
                            game_session && session == game_session;
        for (uint32_t e = 0; e < kMaxGuestEpochs && !f.session_is_guest; ++e) {
            const uintptr_t s2 = server_epoch_session(e);
            f.session_is_guest = s2 && session == s2;
        }
    }
    uint32_t key = 0;
    const uint32_t user2_character = server_user2_player_key();
    f.character_is_user2 = character && user2_character && peek(character + kActorKey, key) && key == user2_character;
    if (facts) *facts = f;
    return gsv::classify_owner(f);
}

// P8 S35 phase E: SavePlayerToSlot / FlushPendingSaveData calls already open on this thread (0 = not nested), for
// the host save journal (the audit's "nested contexts", S34 §5 item 2: observed, not resolved).
thread_local uint32_t t_save_depth = 0;
struct DepthScope {
    DepthScope() { ++t_save_depth; }
    ~DepthScope() { --t_save_depth; }
    DepthScope(const DepthScope&) = delete;
    DepthScope& operator=(const DepthScope&) = delete;
};
// A user actor (the lobby's load) or a character (+0xA0 = its user, set before LoadSlot: .xtls 0x1042AB16 reads it
// for the 3093 character and dereferences it unchecked before the call at 0x1042ABF3; 0x186E5DD for a save), as
// identity_probe tells them.
Owner owner_of_actor(uintptr_t actor, bool& self, uintptr_t& user) {
    user = identity_owner(actor, g_base + profile::rva(off::kServerUserActorVtable), self);
    return owner_of_user(user, self ? 0 : actor);
}

bool bytes_ok(uintptr_t rva, const uint8_t* bytes, size_t n, const char* what) {
    uint8_t actual[64] = {};
    if (n <= sizeof actual && game::safe_read(g_base + rva, actual, n) && std::memcmp(actual, bytes, n) == 0) return true;
    log::warn("Session2 guest save: {} (exe+0x{:X}) is not the expected code", what, rva);
    return false;
}

bool call_site_ok(const CallSite& s) {
    uint8_t b[5] = {};
    int32_t rel = 0;
    if (!game::safe_read(g_base + s.at, b, sizeof b)) return false;
    std::memcpy(&rel, b + 1, 4);
    return b[0] == 0xE8 && s.at + 5 + static_cast<int64_t>(rel) == s.target;
}

// The error code the game keeps in `e.global`, after checking that `e.at` is mov eax,[rip+rel32] to it. 0 = no.
int32_t error_code(const ErrorSite& e) {
    uint8_t b[6] = {};
    int32_t rel = 0, value = 0;
    if (!game::safe_read(g_base + e.at, b, sizeof b) || b[0] != 0x8B || b[1] != 0x05) return 0;
    std::memcpy(&rel, b + 2, 4);
    if (e.at + 6 + static_cast<int64_t>(rel) != e.global) return 0;
    return peek(g_base + e.global, value) ? value : 0;
}

// ---------------------------------------------------------------- files (the mod's own, outside the game's view)

bool exists(const std::wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }

bool read_file(const std::wstring& path, std::vector<uint8_t>& out, uint64_t max, uint64_t& size, DWORD& error) {
    out.clear();
    size = 0;
    error = 0;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    LARGE_INTEGER li{};
    bool ok = GetFileSizeEx(h, &li) != FALSE;
    if (ok) size = static_cast<uint64_t>(li.QuadPart);
    if (ok && size > max) {
        error = ERROR_FILE_TOO_LARGE;
        ok = false;
    }
    if (ok) {
        out.resize(static_cast<size_t>(size));
        DWORD got = 0;
        ok = size == 0 || (ReadFile(h, out.data(), static_cast<DWORD>(size), &got, nullptr) && got == size);
        if (!ok) error = GetLastError();
    } else if (!error) {
        error = GetLastError();
    }
    CloseHandle(h);
    if (!ok) out.clear();
    return ok;
}

bool write_file(const std::wstring& path, std::span<const uint8_t> data, DWORD& error) {
    error = 0;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }
    DWORD put = 0;
    const bool ok = data.empty() || (WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &put, nullptr) &&
                                     put == data.size());
    if (!ok) error = GetLastError();
    const bool closed = CloseHandle(h) != FALSE;
    return ok && closed;
}

bool make_dir(const std::wstring& p) { return CreateDirectoryW(p.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS; }

// A folder the mod made itself (a slot folder, a staging folder, a generation): its known files, then the folder.
// Anything else in it stays (and the folder with it).
bool remove_own_folder(const std::wstring& dir) {
    if (!exists(dir)) return true;
    for (const wchar_t* f : {L"lobby.save", L"save.save", L"manifest.txt"}) {
        const std::wstring p = dir + L"\\" + f;
        if (exists(p)) {
            SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(p.c_str());
        }
    }
    return RemoveDirectoryW(dir.c_str()) != FALSE;
}

bool sha256(std::span<const uint8_t> data, std::array<uint8_t, 32>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const NTSTATUS st = BCryptHash(alg, nullptr, 0, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()),
                                   out.data(), static_cast<ULONG>(out.size()));
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0;
}

struct CheckedFile {
    std::vector<uint8_t> bytes;
    uint64_t size = 0;
    gsv::HeaderInfo header;
    std::string sha;
};

// Reads `dir\<kind>.save` whole and checks it as the game would. why = what failed.
bool read_checked(const std::wstring& dir, FileKind kind, CheckedFile& f, std::string& why) {
    const std::wstring path = dir + L"\\" + gsv::file_kind_file(kind);
    DWORD error = 0;
    if (!read_file(path, f.bytes, gsv::kMaxFileSize, f.size, error)) {
        why = std::format("cannot read '{}' (error {}{})", narrow(path), error,
                          error == ERROR_FILE_TOO_LARGE ? ", larger than 16 MB" : "");
        return false;
    }
    const gsv::HeaderCheck c = gsv::check_header(f.bytes, f.size, &f.header);
    if (c != gsv::HeaderCheck::Ok) {
        why = std::format("'{}' ({} bytes): {}", narrow(path), f.size, gsv::header_check_name(c));
        return false;
    }
    std::array<uint8_t, 32> digest{};
    f.sha = sha256(f.bytes, digest) ? gsv::hex(digest) : std::string("(sha256 failed)");
    return true;
}

// Only the header of `dir\<kind>.save` (and the file's size), checked.
bool read_header(const std::wstring& dir, FileKind kind, gsv::Header& h, std::string& why) {
    const std::wstring path = dir + L"\\" + gsv::file_kind_file(kind);
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        why = std::format("cannot open '{}' (error {})", narrow(path), GetLastError());
        return false;
    }
    LARGE_INTEGER li{};
    DWORD got = 0;
    const bool ok = GetFileSizeEx(f, &li) && ReadFile(f, h.data(), static_cast<DWORD>(h.size()), &got, nullptr) &&
                    got == h.size();
    CloseHandle(f);
    if (!ok) {
        why = std::format("cannot read the header of '{}'", narrow(path));
        return false;
    }
    const gsv::HeaderCheck c = gsv::check_header(h, static_cast<uint64_t>(li.QuadPart));
    if (c != gsv::HeaderCheck::Ok) {
        why = std::format("'{}': {}", narrow(path), gsv::header_check_name(c));
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- the game's slot (server thread, busy section)

// P8 review I1 (game_fault.h): an exception inside the game's code is the game's: the mode switches off, one line
// goes straight to the log and the exception is passed on (never swallowed).
int call_fault(EXCEPTION_POINTERS* ep, const char* where) noexcept {
    g_bits.fetch_or(kDisabled);
    return game::game_fault_continue(ep, "GuestSave", where);
}
bool guarded_get_or_create(uintptr_t store, uintptr_t& slot) noexcept {
    __try {
        slot = g_get_or_create(store, g_slot_name, 0);
        return true;
    } __except (call_fault(GetExceptionInformation(), "0x2355EC0 GetOrCreateSlot(S, guest slot, 0)")) {
        return false;  // never reached: the filter passes it on
    }
}
bool guarded_add_file(uintptr_t slot, const char* name) noexcept {
    __try {
        g_add_file(slot, name);
        return true;
    } __except (call_fault(GetExceptionInformation(), "0x235B100 AddFile(guest slot, lobby/save)")) {
        return false;
    }
}

// The game's memory for gsv::read_slot_files (guarded reads only).
struct GameMem {
    bool read(uintptr_t a, void* out, size_t n) const { return game::safe_read(a, out, n); }
};

// The slot's files as the game keeps them: the name vector (+0x688, char*) and the name -> file object map (+0x08,
// the one the loader looks up). See guest_save_logic.h ("the real layout").
gsv::SlotFilesView scan_slot(uintptr_t slot) { return gsv::read_slot_files(GameMem{}, slot); }

// The guest slot in the store S, made with the game's own functions when missing (what the start-up enumeration
// 0x2358EF0 does for a folder: GetOrCreate + AddFile per file). 0 = failed (why, with every name read).
uintptr_t register_slot(uintptr_t store, std::string& why) {
    uintptr_t slot = 0;
    if (!guarded_get_or_create(store, slot) || !slot) {
        why = "GetOrCreateSlot returned no slot";
        return 0;
    }
    uint8_t memory_only = 1, in_memory = 1;
    if (!peek(slot + kSlotMemoryOnly, memory_only) || !peek(slot + kSlotInMemory, in_memory) ||
        !gsv::slot_flags_disk(memory_only, in_memory)) {
        why = std::format("slot 0x{:X} is not a disk slot (+0x699 {} +0x69C {}): its load would read nothing", slot,
                          memory_only, in_memory);
        return 0;
    }
    gsv::SlotFilesView s = scan_slot(slot);
    if (!s.ok) {
        why = std::format("slot 0x{:X}: its files cannot be read: {}", slot, gsv::describe_slot_files(s));
        return 0;
    }
    const gsv::FilesPlan plan = gsv::plan_slot_files(s.names, s.mapped);
    if (plan == gsv::FilesPlan::Duplicate || plan == gsv::FilesPlan::Inconsistent) {
        why = std::format("slot 0x{:X}: {}: {}", slot, gsv::files_plan_name(plan), gsv::describe_slot_files(s));
        return 0;
    }
    const bool add_lobby = plan == gsv::FilesPlan::AddBoth || plan == gsv::FilesPlan::AddLobby;
    const bool add_save = plan == gsv::FilesPlan::AddBoth || plan == gsv::FilesPlan::AddSave;
    if (add_lobby && !guarded_add_file(slot, "lobby")) return 0;
    if (add_save && !guarded_add_file(slot, "save")) return 0;
    if (add_lobby || add_save) {
        c_files_added.fetch_add((add_lobby ? 1 : 0) + (add_save ? 1 : 0));
        s = scan_slot(slot);
        if (!s.ok || gsv::plan_slot_files(s.names, s.mapped) != gsv::FilesPlan::Ready || !s.lobby || !s.save) {
            why = std::format("slot 0x{:X}: after AddFile the files are not lobby + save: {}", slot,
                              gsv::describe_slot_files(s));
            return 0;
        }
        if (g_lines_phase.take(false)) {
            log::info("Session2 guest save: {} registered in the game's store: slot 0x{:X} ({}): {}", g_slot_name, slot,
                      gsv::files_plan_name(plan), gsv::describe_slot_files(s));
        }
    } else if (!s.lobby || !s.save) {
        why = std::format("slot 0x{:X}: no file object for lobby or save: {}", slot, gsv::describe_slot_files(s));
        return 0;
    }
    return slot;
}


// ---------------------------------------------------------------- the load (0x20688A0, shared hook)

struct LoadFrame {
    bool ours = false;
    uintptr_t actor = 0, slot = 0;
    FileKind kind = FileKind::Lobby;
    gsv::Header expected{};
    uint64_t reads_before = 0;
};
thread_local LoadFrame t_frame;

// Review item 3: the slot phase runs only inside LoadSlot's own call of LoadComponentsFromFile (0x20688A0's only
// caller, which calls it only after taking the manager's busy byte +0x60, 0x186F6BF..6C5, and releases it after),
// and only for the actor whose load load_slot_detour remapped to the guest slot.
struct LoadSlotCall {
    int depth = 0;
    uintptr_t actor = 0;
    bool remapped = false;
};
thread_local LoadSlotCall t_load_slot;

// Moves a staged slot in (under g_mu): sandbox slot204 -> staging slot204.old (an older .old removed first),
// staging slot204.incoming -> sandbox slot204 (renames: the same volume).
bool move_in(std::string& why) {
    if (exists(g_old_dir) && !remove_own_folder(g_old_dir)) {
        why = std::format("cannot remove the previous '{}' (error {})", narrow(g_old_dir), GetLastError());
        return false;
    }
    if (exists(g_slot_dir) && !MoveFileExW(g_slot_dir.c_str(), g_old_dir.c_str(), 0)) {
        why = std::format("cannot rename '{}' to '{}' (error {})", narrow(g_slot_dir), narrow(g_old_dir),
                          GetLastError());
        return false;
    }
    if (!MoveFileExW(g_incoming.c_str(), g_slot_dir.c_str(), 0)) {
        const DWORD e = GetLastError();
        if (exists(g_old_dir) && !exists(g_slot_dir)) MoveFileExW(g_old_dir.c_str(), g_slot_dir.c_str(), 0);
        why = std::format("cannot rename '{}' to '{}' (error {})", narrow(g_incoming), narrow(g_slot_dir), e);
        return false;
    }
    return true;
}

bool refuse_load(int* res, int32_t code, const std::string& why, bool disable) {
    if (disable) set_bits(kDisabled);
    if (res) *res = code;
    log::error("Session2 guest save: the load of {} is REFUSED ({}); result 0x{:X}{}", g_slot_name, why,
               static_cast<uint32_t>(code), disable ? "; own-save mode is OFF for the rest of this run" : "");
    return true;
}

bool phase_before(uintptr_t actor, int* res, uintptr_t store, uintptr_t name, uint32_t slot) noexcept {
    t_frame.ours = false;
    if (g_mode.load(std::memory_order_relaxed) != Mode::On || slot != gsv::kGuestSlot) return false;
    try {
        if (t_load_slot.depth == 0 || t_load_slot.actor != actor || !t_load_slot.remapped) {
            return refuse_load(res, g_err_absent,
                               std::format("actor 0x{:X}: not inside a LoadSlot call this mod remapped (LoadSlot "
                                           "depth {}, its actor 0x{:X})",
                                           actor, t_load_slot.depth, t_load_slot.actor),
                               false);
        }
        char given[16] = {};
        game::safe_read(name, given, sizeof given - 1);
        bool self = false;
        uintptr_t user = 0;
        const Owner owner = owner_of_actor(actor, self, user);
        if (owner != Owner::User2) {
            return refuse_load(res, g_err_invalid,
                               std::format("actor 0x{:X} ('{}') is {}: the guest's slot is user 2's only", actor, given,
                                           gsv::owner_name(owner)),
                               false);
        }
        if (!on_server_thread()) return refuse_load(res, g_err_absent, "not on the server's thread", true);
        if (save_hooks_redirect_failed() || !save_hooks_redirecting()) {
            return refuse_load(res, g_err_absent, "the save redirect is not healthy", true);
        }
        uint8_t byte1 = 0xFF;
        const uintptr_t descriptor = peekp(actor + kActorDescriptor);
        if (!descriptor || !peek(descriptor + 1, byte1)) {
            return refuse_load(res, g_err_absent, std::format("actor 0x{:X}'s descriptor is unreadable", actor), false);
        }
        const FileKind kind = gsv::load_kind(byte1);
        std::string why;
        {
            std::lock_guard lock(g_mu);
            const gsv::SlotState s = state_now();
            if (s.disabled || s.poisoned) {
                return refuse_load(res, g_err_absent, s.poisoned ? "poisoned in this run" : "disabled in this run", false);
            }
            // A staged slot moves in only at a lobby load (a login starts with its lobby), never between the
            // lobby and the character of one login: the pair always comes from one slot.
            if (s.staged && kind == FileKind::Lobby) {
                if (!move_in(why)) return refuse_load(res, g_err_absent, why, true);
                set_bits(kLive);
                clear_bits(kStaged | kLobbyOk | kSaveOk);
                g_live_label = g_staged_label;
                c_moved_in.fetch_add(1);
                log::info("Session2 guest save: the staged guest slot moved in: '{}' -> '{}' (the previous one, if "
                          "any, is '{}') | guest {}, its slot{}, line {}",
                          narrow(g_incoming), narrow(g_slot_dir), narrow(g_old_dir), g_live_label.guest,
                          g_live_label.guest_slot ? std::to_string(*g_live_label.guest_slot) : std::string("?"),
                          g_live_label.lineage_root.empty() ? std::string("none")
                                                            : g_live_label.lineage_root.substr(0, 16) + "...");
            } else if (!s.live) {
                return refuse_load(res, g_err_absent, "nothing staged or live", false);
            }
        }
        LoadFrame f;
        if (!read_header(g_slot_dir, kind, f.expected, why)) return refuse_load(res, g_err_absent, why, true);
        f.slot = register_slot(store, why);
        if (!f.slot) return refuse_load(res, g_err_absent, why, true);
        f.ours = true;
        f.actor = actor;
        f.kind = kind;
        f.reads_before = save_hooks_watch_reads(kind == FileKind::Save);
        t_frame = f;
        if (g_lines_phase.take(false)) {
            log::info("Session2 guest save: user 2's {} loads from {} (actor 0x{:X}{}, store 0x{:X}, slot 0x{:X}) | {}",
                      gsv::file_kind_name(kind), g_slot_name, actor, self ? ", its user actor" : "", store, f.slot,
                      thread_text());
        }
        return false;
    } catch (...) {
        // Only the mod's own steps throw (no memory): fail closed.
        set_bits(kDisabled);
        if (res) *res = g_err_absent;
        return true;
    }
}

void phase_after(uintptr_t actor, const int* r, uint32_t slot) noexcept {
    if (!t_frame.ours || t_frame.actor != actor || slot != gsv::kGuestSlot) return;
    const LoadFrame f = t_frame;
    t_frame.ours = false;
    try {
        int32_t code = -1;
        if (!peek(reinterpret_cast<uintptr_t>(r), code) || code != 0) {
            g_last_error.store(static_cast<uint32_t>(code));
            drop_verification(gsv::drop_on_load_result(false, code ? code : -1));
            log::warn("Session2 guest save: the game's load of the guest's {} returned 0x{:X} (nothing to verify; the "
                      "login fails natively)",
                      gsv::file_kind_name(f.kind), static_cast<uint32_t>(code));
            return;
        }
        // The pair belongs to one login: the character's user must be the user actor whose lobby was verified.
        const uintptr_t login_user = f.kind == FileKind::Lobby ? actor : peekp(actor + kActorUser);
        if (f.kind == FileKind::Save && (!login_user || login_user != g_verified_user.load())) {
            drop_verification({false, true});
            log::warn("Session2 guest save: user 2's character 0x{:X} (user 0x{:X}) loaded, but its login's lobby was "
                      "not verified (verified user 0x{:X}): its saves stay refused",
                      actor, login_user, g_verified_user.load());
            return;
        }
        const gsv::SlotFilesView s = scan_slot(f.slot);
        const uintptr_t obj = !s.ok ? 0 : f.kind == FileKind::Lobby ? s.lobby : s.save;
        gsv::Header loaded{};
        const bool read = obj && game::safe_read(obj + kFileHeader, loaded.data(), loaded.size());
        const bool same = read && gsv::header_matches(loaded, f.expected);
        const uint64_t reads_after = save_hooks_watch_reads(f.kind == FileKind::Save);
        const bool seen = reads_after > f.reads_before;
        if (same && seen) {
            if (f.kind == FileKind::Lobby) g_verified_user.store(login_user);
            set_bits(f.kind == FileKind::Lobby ? kLobbyOk : kSaveOk);
            c_verified.fetch_add(1);
            log::info("Session2 guest save: user 2's {} VERIFIED: the game read '{}\\{}' (redirected reads {} -> {}) "
                      "and its header at file object 0x{:X}+0x98 is the file's | state {}",
                      gsv::file_kind_name(f.kind), narrow(g_slot_dir), narrow(gsv::file_kind_file(f.kind)),
                      f.reads_before, reads_after, obj, state_text(state_now()));
            return;
        }
        set_bits(kPoisoned);
        log::error("Session2 guest save: user 2's {} load returned 0 but is POISONED: {}{} | no more loads or saves of "
                   "user 2 in this run",
                   gsv::file_kind_name(f.kind),
                   !obj ? "its file object is not in the slot's name map (" + gsv::describe_slot_files(s) + ")"
                   : !read ? std::string("its header is unreadable")
                   : !same ? std::string("the header at +0x98 is not the file's")
                           : std::string(),
                   seen ? "" : std::format("{}the save guard saw no read of the file (reads {})",
                                           (!obj || !read || !same) ? "; " : "", reads_after));
    } catch (...) {
        set_bits(kPoisoned);
    }
}

// ---------------------------------------------------------------- the mailbox (after a save of the guest slot)

std::string utc_now() {
    SYSTEMTIME t{};
    GetSystemTime(&t);
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
                       t.wSecond);
}
uint64_t unix_now() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    const uint64_t ticks = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return ticks / 10000000ull - 11644473600ull;
}

std::vector<uint32_t> list_generations(const std::wstring& dir) {
    std::vector<uint32_t> g;
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileExW((dir + L"\\gen*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (f == INVALID_HANDLE_VALUE) return g;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (const auto n = gsv::parse_generation(fd.cFileName)) g.push_back(*n);
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    return g;
}

bool export_slot(gsv::SaveCaller caller, uint32_t asked, std::string& why) {
    // The live pair's label, then its files: a pair that moves in between the two would give one pair's content
    // under the other's label (review of 12f8dfb, item 2), so the move-in count must not change meanwhile.
    GuestSaveLabel label;
    uint64_t moved_before = 0;
    {
        std::lock_guard lock(g_mu);
        label = g_live_label;
        moved_before = c_moved_in.load();
        if (label.guest.empty()) label.guest = g_guest_id;
    }
    CheckedFile lobby, save;
    if (!read_checked(g_slot_dir, FileKind::Lobby, lobby, why) || !read_checked(g_slot_dir, FileKind::Save, save, why)) {
        return false;
    }
    {
        std::lock_guard lock(g_mu);
        if (c_moved_in.load() != moved_before) {
            why = "another staged pair moved in while the slot was read (its label would not match its files)";
            return false;
        }
    }
    const std::string& guest = label.guest;
    const std::optional<uint32_t>& guest_slot = label.guest_slot;
    const std::string& root = label.lineage_root;
    const std::wstring dir = g_mailbox_root + L"\\" + widen(gsv::guest_folder_name(guest));
    const std::wstring cdmp = g_mailbox_root.substr(0, g_mailbox_root.rfind(L'\\'));
    if (!make_dir(cdmp) || !make_dir(g_mailbox_root) || !make_dir(dir)) {
        why = std::format("cannot create '{}' (error {})", narrow(dir), GetLastError());
        return false;
    }
    std::vector<uint32_t> gens = list_generations(dir);
    // Phase B review: never at or below what the guest already has (its base_gen / acknowledged), even if this
    // mailbox folder was emptied since.
    const uint32_t gen = gsv::next_generation_above(gens, g_gen_floor.load());
    if (!gen) {
        why = "no generation number left";
        return false;
    }
    const std::wstring final_dir = dir + std::format(L"\\gen{}", gen);
    const std::wstring partial = final_dir + L".partial";
    remove_own_folder(partial);
    DWORD error = 0;
    gsv::Manifest m;
    m.generation = gen;
    m.guest = guest;
    m.reason = std::format("{} (ret {})", gsv::save_caller_name(caller),
                           caller == gsv::SaveCaller::Autosave     ? rva_text(addrs().rets.autosave)
                           : caller == gsv::SaveCaller::Manual2910 ? rva_text(addrs().rets.manual2910)
                                                                   : std::string("?"));
    m.host_slot = gsv::kGuestSlot;
    m.asked_slot = asked;
    m.time_utc = utc_now();
    m.time_unix = unix_now();
    m.guest_slot = guest_slot;
    m.lineage_root = root;
    m.lineage_base = label.lineage_base;
    m.files = {{"lobby.save", lobby.size, lobby.sha, lobby.header}, {"save.save", save.size, save.sha, save.header}};
    const std::string text = gsv::manifest_text(m);
    if (!make_dir(partial) || !write_file(partial + L"\\lobby.save", lobby.bytes, error) ||
        !write_file(partial + L"\\save.save", save.bytes, error) ||
        !write_file(partial + L"\\manifest.txt",
                    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()), error) ||
        !MoveFileExW(partial.c_str(), final_dir.c_str(), 0)) {
        why = std::format("cannot write '{}' (error {})", narrow(final_dir), error ? error : GetLastError());
        remove_own_folder(partial);
        return false;
    }
    gens.push_back(gen);
    std::string dropped;
    for (const uint32_t old : gsv::generations_to_drop(gens)) {
        const bool ok = remove_own_folder(dir + std::format(L"\\gen{}", old));
        dropped += std::format(" gen{}{}", old, ok ? "" : " (NOT removed)");
    }
    g_last_gen.store(gen);
    log::info("Session2 guest save: EXPORTED gen{} to '{}' ({}; lobby {} B sha256 {}, save {} B sha256 {}) | the guest's "
              "slot{}, line {}{}",
              gen, narrow(final_dir), m.reason, lobby.size, lobby.sha, save.size, save.sha,
              guest_slot ? std::to_string(*guest_slot) : std::string("?"),
              root.empty() ? std::string("none (never applied by the guest's script)") : root.substr(0, 16) + "...",
              dropped.empty() ? "" : " | older dropped:" + dropped);
    if (const GuestSaveResultFn fn = g_result_fn.load(std::memory_order_acquire)) {
        GuestSaveExport e;
        e.generation = gen;
        e.folder = final_dir;
        e.reason = m.reason;
        e.lobby_size = lobby.size;
        e.save_size = save.size;
        e.lobby_sha256 = lobby.sha;
        e.save_sha256 = save.sha;
        e.guest = guest;
        e.guest_slot = m.guest_slot;
        e.lineage_root = m.lineage_root;
        e.lineage_base = m.lineage_base;
        e.time_unix = m.time_unix;
        fn(e);
    }
    return true;
}

// ---------------------------------------------------------------- the entry hooks

int* __fastcall load_slot_detour(uintptr_t mgr, int* res, uint32_t slot, uintptr_t actor) noexcept {
    const uint64_t ret = rva_of(_ReturnAddress());
    const Mode mode = g_mode.load(std::memory_order_relaxed);
    const gsv::LoadCaller caller = gsv::load_caller(ret, addrs().rets);
    bool self = false;
    uintptr_t user = 0;
    const Owner owner = owner_of_actor(actor, self, user);
    const gsv::SlotState s = state_now();
    const gsv::Decision d = gsv::decide_load(mode, owner, caller, s, slot, gsv::kGuestSlot);
    c_load_calls.fetch_add(1, std::memory_order_relaxed);
    const bool mine = owner != Owner::Host || slot == gsv::kGuestSlot;
    const bool user2_on = mode == Mode::On && owner == Owner::User2;
    if (owner == Owner::User2) c_load_user2.fetch_add(1, std::memory_order_relaxed);
    // Review item 4: a new load of user 2 (its lobby: a login; its character) invalidates the earlier verification.
    if (user2_on) drop_verification(gsv::drop_on_load_entry(self));
    bool logged = false;
    try {
        if (g_lines_load.take(!mine)) {
            logged = true;
            const gsv::Decision would = gsv::decide_load_on(owner, caller, s, slot, gsv::kGuestSlot);
            log::info("Session2 guest save probe: LoadSlot 0x186F570 from {} ({}) | actor 0x{:X}{} of user 0x{:X} = {} "
                      "| slot {} -> {} {} ({}){} | state {} | {}",
                      rva_text(ret), gsv::load_caller_name(caller), actor, self ? " (user actor)" : "", user,
                      gsv::owner_name(owner), slot, gsv::action_name(d.action), d.slot, d.why,
                      mode == Mode::Probe ? std::format(" | mode 1 WOULD: {} {} ({})", gsv::action_name(would.action),
                                                        would.slot, would.why)
                                          : std::string(),
                      state_text(s), thread_text());
        }
    } catch (...) {
    }
    if (d.action == Action::Refuse) {
        c_load_refused.fetch_add(1, std::memory_order_relaxed);
        if (user2_on) drop_verification(gsv::drop_on_load_result(true, 0));
        *res = owner == Owner::User2 ? g_err_busy : g_err_invalid;
        return res;
    }
    if (d.action == Action::Remap) c_load_remapped.fetch_add(1, std::memory_order_relaxed);
    // Review item 3: the slot phase in 0x20688A0 runs only inside this call, for this actor, when remapped.
    const LoadSlotCall outer = t_load_slot;
    t_load_slot = {outer.depth + 1, actor, d.action == Action::Remap};
    int* r = g_h_load_slot.unsafe_call<int*>(mgr, res, d.slot, actor);
    t_load_slot = outer;
    if (user2_on) {
        int32_t code = -1;
        if (!peek(reinterpret_cast<uintptr_t>(r), code)) code = -1;
        drop_verification(gsv::drop_on_load_result(false, code));
    }
    if (logged) {
        try {
            int32_t code = -1;
            const bool ok = peek(reinterpret_cast<uintptr_t>(r), code);
            log::info("Session2 guest save probe: LoadSlot from {} actor 0x{:X} slot {} returned {}{}", rva_text(ret),
                      actor, d.slot, ok ? std::format("0x{:X}", static_cast<uint32_t>(code)) : std::string("unreadable"),
                      d.action == Action::Remap ? std::format(" | state {}", state_text(state_now())) : std::string());
        } catch (...) {
        }
    }
    return r;
}

int* __fastcall save_detour(uintptr_t mgr, int* res, uint32_t slot, uintptr_t character, uintptr_t opts) noexcept {
    const uint64_t ret = rva_of(_ReturnAddress());
    const Mode mode = g_mode.load(std::memory_order_relaxed);
    const gsv::SaveCaller caller = gsv::save_caller(ret, addrs().rets);
    const uintptr_t user = peekp(character + kActorUser);
    gsv::UserFacts facts;
    const Owner owner = owner_of_user(user, character, &facts);
    const gsv::SlotState s = state_now();
    // P8 S35 phase E: the host save journal's event (observation only; nothing here decides anything).
    hsv::SaveEvent ev;
    ev.owner = owner;
    ev.positive_host = hsv::positive_host(facts);
    ev.asked = slot;
    ev.depth = t_save_depth;
    try {
        ev.caller = gsv::save_caller_name(caller);  // short literals (no allocation in practice); nothing may escape
    } catch (...) {
    }
    // The login whose two files were verified, and still session 2's user (a queued autosave after its logout is not).
    uintptr_t u2 = 0;
    const bool same_login = user && user == g_verified_user.load() && server_user2(u2) && u2 == user;
    const gsv::Decision d = gsv::decide_save(mode, owner, s, same_login, slot, gsv::kGuestSlot);
    c_save_calls.fetch_add(1, std::memory_order_relaxed);
    if (owner == Owner::User2) c_save_user2.fetch_add(1, std::memory_order_relaxed);
    const bool mine = owner != Owner::Host || slot == gsv::kGuestSlot;
    bool logged = false;
    try {
        if (g_lines_save.take(!mine)) {
            logged = true;
            uint32_t options = 0;
            const bool opts_ok = peek(opts, options);
            const gsv::Decision would = gsv::decide_save_on(owner, s, same_login, slot, gsv::kGuestSlot);
            log::info("Session2 guest save probe: SavePlayerToSlot 0x186E450 from {} ({}) | character 0x{:X} of user "
                      "0x{:X} = {} | slot {} options {} -> {} {} ({}){} | state {} | {}",
                      rva_text(ret), gsv::save_caller_name(caller), character, user, gsv::owner_name(owner), slot,
                      opts_ok ? std::format("0x{:X}", options) : std::string("unreadable"), gsv::action_name(d.action),
                      d.slot, d.why,
                      mode == Mode::Probe ? std::format(" | mode 1 WOULD: {} {} ({})", gsv::action_name(would.action),
                                                        would.slot, would.why)
                                          : std::string(),
                      state_text(s), thread_text());
        }
    } catch (...) {
    }
    try {
        ev.action = gsv::action_name(d.action);
    } catch (...) {
    }
    if (d.action == Action::Refuse) {
        c_save_refused.fetch_add(1, std::memory_order_relaxed);
        *res = g_err_save;
        ev.written = hsv::kNoSlot;  // nothing written
        ev.result_read = true;
        ev.result = g_err_save;
        ev.redirect_failed = save_hooks_redirect_failed();
        host_save_observe_save(ev);
        return res;
    }
    if (d.action == Action::Remap) c_save_remapped.fetch_add(1, std::memory_order_relaxed);
    int* r = nullptr;
    {
        // An SEH unwind through here would leave the depth raised: later saves on this thread then read as nested
        // (probe says unknown), the conservative side.
        const DepthScope depth;
        r = g_h_save.unsafe_call<int*>(mgr, res, d.slot, character, opts);
    }
    int32_t code = -1;
    const bool code_ok = peek(reinterpret_cast<uintptr_t>(r), code);
    ev.written = d.slot;
    ev.result_read = code_ok;
    ev.result = code;
    ev.redirect_failed = save_hooks_redirect_failed();
    host_save_observe_save(ev);
    try {
        if (logged) {
            log::info("Session2 guest save probe: SavePlayerToSlot from {} character 0x{:X} slot {} returned {}",
                      rva_text(ret), character, d.slot,
                      code_ok ? std::format("0x{:X}", static_cast<uint32_t>(code)) : std::string("unreadable"));
        }
        if (d.action == Action::Remap) {
            std::string why;
            if (!code_ok || code != 0) {
                g_last_error.store(code_ok ? static_cast<uint32_t>(code) : 0xFFFFFFFFu);
                log::warn("Session2 guest save: user 2's save to {} returned {}: nothing exported", g_slot_name,
                          code_ok ? std::format("0x{:X}", static_cast<uint32_t>(code)) : std::string("unreadable"));
            } else if (export_slot(caller, slot, why)) {
                c_exported.fetch_add(1);
            } else {
                c_export_failed.fetch_add(1);
                log::error("Session2 guest save: user 2's save to {} succeeded but the export FAILED: {}", g_slot_name,
                           why);
            }
        }
    } catch (...) {
        c_export_failed.fetch_add(1);
    }
    return r;
}

int* __fastcall flush_detour(uintptr_t mgr, int* res, uintptr_t character, uint64_t counter, uint8_t* opts,
                             int* slot_out) noexcept {
    const uint64_t ret = rva_of(_ReturnAddress());
    int32_t pending = -2;
    uint8_t options = 0;
    const bool pending_ok = peek(mgr + kMgrPendingSlot, pending);
    const bool opts_ok = peek(reinterpret_cast<uintptr_t>(opts), options);
    const uintptr_t user = peekp(character + kActorUser);
    gsv::UserFacts facts;
    const Owner owner = owner_of_user(user, character, &facts);
    c_flush_calls.fetch_add(1, std::memory_order_relaxed);
    if (owner == Owner::User2) c_flush_user2.fetch_add(1, std::memory_order_relaxed);
    const uint32_t depth_before = t_save_depth;
    int* r = nullptr;
    {
        const DepthScope depth;
        r = g_h_flush.unsafe_call<int*>(mgr, res, character, counter, opts, slot_out);
    }
    try {
        // P8 S35 phase E: the journal's event. The committed slot is not recorded: with nothing pending the game does
        // not write it (audit S34 §5: "committed slot 1163343936" was an unwritten out parameter).
        hsv::FlushEvent ev;
        ev.owner = owner;
        ev.positive_host = hsv::positive_host(facts);
        ev.caller = gsv::flush_caller_name(ret, addrs().rets);
        ev.pending_read = pending_ok;
        ev.pending = pending;
        int32_t code = -1;
        ev.result_read = peek(reinterpret_cast<uintptr_t>(r), code);
        ev.result = code;
        ev.depth = depth_before;
        host_save_observe_flush(ev);
    } catch (...) {
    }
    try {
        if (g_lines_flush.take(owner == Owner::Host)) {
            int32_t code = -1, out = -1;
            const bool code_ok = peek(reinterpret_cast<uintptr_t>(r), code);
            const bool out_ok = peek(reinterpret_cast<uintptr_t>(slot_out), out);
            log::info("Session2 guest save probe: FlushPendingSaveData 0x1871930 from {} ({}) | character 0x{:X} of "
                      "user 0x{:X} = {} | options {} counter {} | pending slot +0x5C before {} | committed slot {} | "
                      "returned {} | {}",
                      rva_text(ret), gsv::flush_caller_name(ret, addrs().rets), character, user, gsv::owner_name(owner),
                      opts_ok ? std::format("0x{:X}", options) : std::string("unreadable"),
                      static_cast<uint16_t>(counter), pending,
                      out_ok ? std::format("{}", out) : std::string("unreadable"),
                      code_ok ? std::format("0x{:X}", static_cast<uint32_t>(code)) : std::string("unreadable"),
                      thread_text());
        }
    } catch (...) {
    }
    return r;
}

// ---------------------------------------------------------------- install

// The one all-digit folder in the sandbox (the save root "%#/%#/save/%#" names it after the account, 0x5714110).
bool find_account(const std::wstring& sandbox, std::wstring& account, std::string& why) {
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileExW((sandbox + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (f == INVALID_HANDLE_VALUE) {
        why = std::format("cannot list '{}' (error {})", narrow(sandbox), GetLastError());
        return false;
    }
    std::vector<std::wstring> found;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            continue;
        }
        const std::wstring n = fd.cFileName;
        if (!n.empty() && n.find_first_not_of(L"0123456789") == std::wstring::npos) found.push_back(n);
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    if (found.size() != 1) {
        why = std::format("the sandbox '{}' has {} account folders (all digits); exactly one is needed", narrow(sandbox),
                          found.size());
        return false;
    }
    account = found[0];
    return true;
}

bool stage_debug(const std::wstring& debug_dir) {
    std::string why;
    if (!make_dir(g_incoming)) {
        log::error("Session2 guest save: cannot create '{}' (error {})", narrow(g_incoming), GetLastError());
        return false;
    }
    for (const FileKind k : {FileKind::Lobby, FileKind::Save}) {
        const std::wstring from = debug_dir + L"\\" + gsv::file_kind_file(k);
        const std::wstring to = g_incoming + L"\\" + gsv::file_kind_file(k);
        if (!CopyFileW(from.c_str(), to.c_str(), FALSE)) {
            log::error("Session2 guest save: guest_own_save_debug_dir: cannot copy '{}' to '{}' (error {})",
                       narrow(from), narrow(to), GetLastError());
            return false;
        }
    }
    if (!guest_save_incoming_ready(std::format("guest_own_save_debug_dir '{}'", narrow(debug_dir)), GuestSaveLabel{},
                                   why)) {
        log::error("Session2 guest save: guest_own_save_debug_dir '{}' refused: {}", narrow(debug_dir), why);
        return false;
    }
    return true;
}

bool forced_off(Mode wanted, const std::string& why) {
    log::warn("Session2 guest save: guest_own_save={} is forced OFF: {}", gsv::mode_name(wanted), why);
    return false;
}

}  // namespace

bool guest_save_install(const GuestSaveOptions& opt) {
    if (opt.mode == Mode::Off || g_mode.load() != Mode::Off) return g_mode.load() != Mode::Off;
    static_assert(gsv::guest_slot_allowed(gsv::kGuestSlot));
    if (!save_hooks_redirecting()) return forced_off(opt.mode, "it needs save_guard=redirect active (it is not)");
    if (save_hooks_redirect_failed()) return forced_off(opt.mode, "the save redirect has failed calls");
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const std::wstring sandbox = save_hooks_sandbox_dir();
    std::wstring account;
    std::string why;
    if (sandbox.empty() || !find_account(sandbox, account, why)) return forced_off(opt.mode, why);
    const std::string name = gsv::slot_name(gsv::kGuestSlot);
    std::memcpy(g_slot_name, name.c_str(), name.size() + 1);
    g_account_dir = sandbox + L"\\" + account;
    g_slot_dir = g_account_dir + L"\\" + widen(name);
    // A fresh copy of the real folder: a slot204 there would have come from it (the game built it into its store at
    // start-up), and nothing of the guest's may be loaded over it.
    if (exists(g_slot_dir)) return forced_off(opt.mode, std::format("'{}' already exists in the sandbox", narrow(g_slot_dir)));
    // Staging: a sibling of the save folder and of the sandbox (...\CD\cdmp_guest_save_staging\<account>), which no
    // save path of the game names: the game never lists it, so a staged slot changes nothing it sees (review item 5).
    const size_t cut = sandbox.rfind(L'\\');
    if (cut == std::wstring::npos) return forced_off(opt.mode, "the sandbox path has no parent");
    const std::wstring staging_root = sandbox.substr(0, cut) + L"\\cdmp_guest_save_staging";
    g_staging_dir = staging_root + L"\\" + account;
    g_incoming = g_staging_dir + L"\\" + widen(name) + L".incoming";
    g_old_dir = g_staging_dir + L"\\" + widen(name) + L".old";
    if (!make_dir(staging_root) || !make_dir(g_staging_dir)) {
        return forced_off(opt.mode, std::format("cannot create '{}' (error {})", narrow(g_staging_dir), GetLastError()));
    }
    for (const std::wstring& p : {g_incoming, g_old_dir}) {
        // A previous run's (its sandbox is _prev now): the mod's own folders, removed (known files only).
        if (exists(p) && !remove_own_folder(p)) {
            return forced_off(opt.mode, std::format("cannot remove the previous run's '{}'", narrow(p)));
        }
    }
    wchar_t local[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return forced_off(opt.mode, "%LOCALAPPDATA% not found");
    g_mailbox_root = std::wstring(local) + L"\\cdmp\\guest_saves";
    {
        std::lock_guard lock(g_mu);
        g_guest_id = opt.guest_id.empty() ? std::string("unknown") : opt.guest_id;
    }

    // The code: three entries to hook, two functions to call, the callers and the error codes.
    const Addrs& ad = addrs();
    const bool load_ok = bytes_ok(ad.load_slot, ad.load_head.data(), ad.load_head.size(), "LoadSlot");
    const bool save_ok = bytes_ok(ad.save, ad.save_head.data(), ad.save_head.size(), "SavePlayerToSlot");
    const bool flush_ok = bytes_ok(ad.flush, ad.flush_head.data(), ad.flush_head.size(), "FlushPendingSaveData");
    const bool calls_ok = bytes_ok(ad.get_or_create, ad.get_or_create_head.data(), ad.get_or_create_head.size(), "GetOrCreateSlot") &&
                          bytes_ok(ad.add_file, ad.add_file_head.data(), ad.add_file_head.size(), "AddFile");
    bool sites = true;
    for (const CallSite& s : ad.call_sites) {
        if (!call_site_ok(s)) {
            log::warn("Session2 guest save: the call at exe+0x{:X} is not a call to exe+0x{:X}", s.at, s.target);
            sites = false;
        }
    }
    g_err_busy = error_code(*ad.err_busy);
    g_err_invalid = error_code(*ad.err_invalid);
    g_err_absent = error_code(*ad.err_absent);
    g_err_save = error_code(*ad.err_save);
    Mode mode = opt.mode;
    if (mode == Mode::On) {
        std::string missing;
        if (!load_ok || !save_ok) missing += " the LoadSlot/SavePlayerToSlot entries;";
        if (!calls_ok) missing += " GetOrCreateSlot/AddFile;";
        if (!sites) missing += " the callers;";
        for (const auto& [code, site] : {std::pair{g_err_busy, ad.err_busy}, std::pair{g_err_invalid, ad.err_invalid},
                                         std::pair{g_err_absent, ad.err_absent}, std::pair{g_err_save, ad.err_save}}) {
            if (!code) missing += std::format(" {} ([exe+0x{:X}] is 0 or not read there);", site->what, site->global);
        }
        if (!missing.empty()) return forced_off(mode, "mode 1 cannot fail closed without:" + missing);
    }
    if (!load_ok && !save_ok && !flush_ok) return forced_off(mode, "none of the three entries is the expected code");

    // Mode 1: the slot phase in the shared 0x20688A0 hook goes in first (a remap with no phase would only fail).
    if (mode == Mode::On) {
        GuestSaveLoadCalls calls;
        calls.before = &phase_before;
        calls.after = &phase_after;
        if (!identity_load_hook_share(calls)) {
            return forced_off(mode, "the shared LoadComponentsFromFile 0x20688A0 entry hook could not be installed");
        }
        g_get_or_create = reinterpret_cast<GetOrCreateFn>(g_base + ad.get_or_create);
        g_add_file = reinterpret_cast<AddFileFn>(g_base + ad.add_file);
    }
    save_hooks_watch_folder(g_slot_dir);
    g_mode.store(mode);  // before the hooks go live: a detour never sees the mode half set

    std::string on, off;
    const auto hook = [&](bool ok, uintptr_t at, void* detour, SafetyHookInline& h, const char* what) {
        if (ok) {
            h = safetyhook::create_inline(reinterpret_cast<void*>(g_base + at), detour, SafetyHookInline::StartDisabled);
            if (h && h.enable()) {
                on += std::string(on.empty() ? "" : ", ") + what;
                return true;
            }
            h = {};
        }
        off += std::string(off.empty() ? "" : ", ") + what;
        return false;
    };
    const bool h_load = hook(load_ok, ad.load_slot, reinterpret_cast<void*>(&load_slot_detour), g_h_load_slot,
                             "LoadSlot 0x186F570");
    const bool h_save = hook(save_ok, ad.save, reinterpret_cast<void*>(&save_detour), g_h_save,
                             "SavePlayerToSlot 0x186E450");
    const bool h_flush =
        hook(flush_ok, ad.flush, reinterpret_cast<void*>(&flush_detour), g_h_flush, "FlushPendingSaveData 0x1871930");
    if (mode == Mode::On && (!h_load || !h_save)) {
        // Disabled, not destroyed: a thread may be inside a detour. The shared load phase stays and refuses.
        for (SafetyHookInline* h : {&g_h_load_slot, &g_h_save, &g_h_flush}) {
            if (*h) (void)h->disable();
        }
        set_bits(kDisabled);
        g_mode.store(Mode::Off);
        return forced_off(mode, "the LoadSlot / SavePlayerToSlot hooks could not be enabled");
    }
    host_save_note_hooks(h_save, h_flush);  // P8 S35 phase E: the journal says Save/Flush are observed in this run
    log::warn("Session2 guest save (P8 S25, phase A): guest_own_save={} | {} | slot {} ('{}'; not 207: GetOrCreateSlot "
              "makes 205-207 memory-only) | staging '{}' | mailbox '{}\\{}' | hooks on: {}{} | callers {} | errors: "
              "busy 0x{:X} invalid slot 0x{:X} absent slot 0x{:X} save 0x{:X}",
              gsv::mode_name(mode),
              mode == Mode::On ? "user 2 loads and saves ITS OWN slot in the sandbox; fail closed (never the host's)"
                               : "PROBE: log only (callers, user, slot, result, thread); nothing remapped or refused",
              gsv::kGuestSlot, narrow(g_slot_dir), narrow(g_incoming), narrow(g_mailbox_root),
              gsv::guest_folder_name(opt.guest_id), on.empty() ? "none" : on, off.empty() ? "" : " | OFF: " + off,
              sites ? "checked" : "NOT as expected (mode 1 would refuse)", static_cast<uint32_t>(g_err_busy),
              static_cast<uint32_t>(g_err_invalid), static_cast<uint32_t>(g_err_absent),
              static_cast<uint32_t>(g_err_save));
    if (!opt.debug_dir.empty()) {
        stage_debug(opt.debug_dir);
    } else {
        log::info("Session2 guest save: no guest_own_save_debug_dir: nothing staged (phase B fills '{}')",
                  narrow(g_incoming));
    }
    return true;
}

gsv::Mode guest_save_mode() { return g_mode.load(); }

std::wstring guest_save_incoming_dir() { return g_mode.load() == Mode::Off ? std::wstring() : g_incoming; }

bool guest_save_incoming_ready(const std::string& source, const GuestSaveLabel& label, std::string& why) {
    why.clear();
    if (g_incoming.empty()) {
        why = "guest_own_save is off";
        return false;
    }
    try {
        std::lock_guard lock(g_mu);
        const gsv::SlotState s = state_now();
        if (s.disabled || s.poisoned) {
            why = s.poisoned ? "the guest's save is poisoned in this run" : "own-save mode is off for this run";
            return false;
        }
        CheckedFile lobby, save;
        if (!read_checked(g_incoming, FileKind::Lobby, lobby, why) || !read_checked(g_incoming, FileKind::Save, save, why)) {
            return false;
        }
        // The label first (it may throw: then the folder is not marked staged with the previous one's label).
        g_staged_label = label;
        if (g_staged_label.guest.empty()) g_staged_label.guest = g_guest_id;
        set_bits(kStaged);
        log::info("Session2 guest save: STAGED from {}: lobby {} B v{} sha256 {} | save {} B v{} raw {} sha256 {} | "
                  "guest {}, its slot{}, line {}, base {} | {}",
                  source, lobby.size, lobby.header.version, lobby.sha, save.size, save.header.version,
                  save.header.raw_size, save.sha, g_staged_label.guest,
                  label.guest_slot ? std::to_string(*label.guest_slot) : std::string("?"),
                  label.lineage_root.empty() ? std::string("none") : label.lineage_root.substr(0, 16) + "...",
                  label.lineage_base.empty() ? std::string("none") : label.lineage_base.substr(0, 16) + "...",
                  g_mode.load() == Mode::On
                      ? std::format("user 2's next load moves it in as {}", g_slot_name)
                      : std::string("probe: nothing moves in (mode 1 would load it as the guest's slot)"));
        return true;
    } catch (...) {
        why = "out of memory";
        return false;
    }
}

void guest_save_set_guest_id(const std::string& id) {
    std::lock_guard lock(g_mu);
    g_guest_id = id.empty() ? std::string("unknown") : id;
}

std::string guest_save_guest_id() {
    std::lock_guard lock(g_mu);
    return g_guest_id;
}

bool guest_save_incoming_begin(std::string& why) {
    why.clear();
    if (g_incoming.empty() || g_mode.load() == Mode::Off) {
        why = "guest_own_save is off";
        return false;
    }
    try {
        std::lock_guard lock(g_mu);
        const gsv::SlotState s = state_now();
        if (s.disabled || s.poisoned) {
            why = s.poisoned ? "the guest's save is poisoned in this run" : "own-save mode is off for this run";
            return false;
        }
        // Before a single byte changes: a lobby load from now on takes the live slot (or nothing), never this folder.
        clear_bits(kStaged);
        if (exists(g_incoming) && !remove_own_folder(g_incoming)) {
            why = std::format("cannot empty '{}' (error {})", narrow(g_incoming), GetLastError());
            return false;
        }
        if (!make_dir(g_incoming)) {
            why = std::format("cannot create '{}' (error {})", narrow(g_incoming), GetLastError());
            return false;
        }
        return true;
    } catch (...) {
        why = "out of memory";
        return false;
    }
}

bool guest_save_incoming_write(gsv::FileKind kind, const std::vector<uint8_t>& bytes, std::string& why) {
    if (g_incoming.empty()) {
        why = "guest_own_save is off";
        return false;
    }
    const std::wstring path = g_incoming + L"\\" + gsv::file_kind_file(kind);
    DWORD error = 0;
    if (!write_file(path, bytes, error)) {
        why = std::format("cannot write '{}' (error {})", narrow(path), error ? error : GetLastError());
        return false;
    }
    return true;
}

void guest_save_set_generation_floor(uint32_t floor) {
    uint32_t cur = g_gen_floor.load();
    while (floor > cur && !g_gen_floor.compare_exchange_weak(cur, floor)) {
    }
}

std::wstring guest_save_mailbox_folder(const std::string& guest_id) {
    if (g_mode.load() == Mode::Off || g_mailbox_root.empty()) return {};
    return g_mailbox_root + L"\\" + widen(gsv::guest_folder_name(guest_id));
}

uint64_t guest_save_exports() { return c_exported.load(); }
uint32_t guest_save_last_error() { return g_last_error.load(); }
uint32_t guest_save_last_generation() { return g_last_gen.load(); }

void guest_save_set_result_handler(GuestSaveResultFn fn) { g_result_fn.store(fn, std::memory_order_release); }

gsv::SlotState guest_save_state() { return state_now(); }

std::string guest_save_describe() {
    const Mode mode = g_mode.load();
    if (mode == Mode::Off) return "guest save off";
    return std::format("guest save {}: slot {} {} | LoadSlot calls {} (user 2 {}: remapped {}, refused {}) | saves {} "
                       "(user 2 {}: remapped {}, refused {}) | exported {} (failed {}, last gen {}) | flush {} (user 2 "
                       "{}) | moved in {}, files added {}, verified {}",
                       gsv::mode_name(mode), gsv::kGuestSlot, state_text(state_now()), c_load_calls.load(),
                       c_load_user2.load(), c_load_remapped.load(), c_load_refused.load(), c_save_calls.load(),
                       c_save_user2.load(), c_save_remapped.load(), c_save_refused.load(), c_exported.load(),
                       c_export_failed.load(), g_last_gen.load(), c_flush_calls.load(), c_flush_user2.load(),
                       c_moved_in.load(), c_files_added.load(), c_verified.load());
}

}  // namespace cdmp::session2
