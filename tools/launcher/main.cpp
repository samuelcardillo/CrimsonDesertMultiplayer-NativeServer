// cdmp_launcher.exe: installs or updates the mod, starts the game with or without it, and says who to play with.
// This file is the window only; the work is in launcher_core.cpp and the rules in launcher_logic.h
// (docs/LAUNCHER.md). Everything a player reads here is in English.
//
//   cdmp_launcher.exe                                    normal use, from the kit folder
//   cdmp_launcher.exe --game-dir <bin64> --data-dir <dir> --bundle <kit folder> --no-launch     for testing

#include <windows.h>

#include <d3d11.h>
#include <objbase.h>
#include <shellapi.h>
#include <shobjidl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "launcher_core.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {
namespace fs = std::filesystem;
using namespace cdmp::launcher;

constexpr int kWidth = 780, kHeight = 730;  // of the window's inside, before the screen's scale
constexpr wchar_t kWindowClass[] = L"cdmp_launcher";

const ImVec4 kAccent(0.80f, 0.22f, 0.20f, 1.0f);
const ImVec4 kAccentHover(0.90f, 0.30f, 0.27f, 1.0f);
const ImVec4 kAccentActive(0.68f, 0.17f, 0.16f, 1.0f);
const ImVec4 kGood(0.45f, 0.80f, 0.50f, 1.0f);
const ImVec4 kWarn(0.95f, 0.75f, 0.35f, 1.0f);
const ImVec4 kBad(1.00f, 0.45f, 0.40f, 1.0f);

// ---------------------------------------------------------------- Direct3D 11 (as Dear ImGui's example)
ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_context = nullptr;
IDXGISwapChain* g_swap_chain = nullptr;
ID3D11RenderTargetView* g_target = nullptr;
UINT g_resize_width = 0, g_resize_height = 0;
bool g_occluded = false;

void create_target() {
    ID3D11Texture2D* back = nullptr;
    if (SUCCEEDED(g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back))) && back) {
        g_device->CreateRenderTargetView(back, nullptr, &g_target);
        back->Release();
    }
}

void release_target() {
    if (g_target) g_target->Release(), g_target = nullptr;
}

bool create_device(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level{};
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
                                               D3D11_SDK_VERSION, &sd, &g_swap_chain, &g_device, &level, &g_context);
    if (FAILED(hr)) {  // no usable graphics driver: the software one is enough for a few buttons
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION,
                                           &sd, &g_swap_chain, &g_device, &level, &g_context);
    }
    if (FAILED(hr)) return false;
    create_target();
    return g_target != nullptr;
}

void release_device() {
    release_target();
    if (g_swap_chain) g_swap_chain->Release(), g_swap_chain = nullptr;
    if (g_context) g_context->Release(), g_context = nullptr;
    if (g_device) g_device->Release(), g_device = nullptr;
}

LRESULT WINAPI window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (wparam != SIZE_MINIMIZED) {
            g_resize_width = LOWORD(lparam);
            g_resize_height = HIWORD(lparam);
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wparam & 0xFFF0) == SC_KEYMENU) return 0;  // no Alt menu
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

// ---------------------------------------------------------------- state
// What a look at this PC found; replaced as a whole when the worker has a new one.
struct Snapshot {
    SteamInfo steam;
    GameInfo game;
    FolderState folder;
    Catalog catalog;
    int chosen = -1;  // the package to play with: an index in catalog.sources
    bool stated = false;

    const Source* source() const { return chosen >= 0 ? &catalog.sources[static_cast<size_t>(chosen)] : nullptr; }
};

struct App {
    HWND hwnd = nullptr;
    float scale = 1.0f;
    ImFont* bold = nullptr;
    bool no_launch = false;
    fs::path forced_game_dir;  // --game-dir: not saved

    Paths paths;
    Settings settings;
    std::shared_ptr<const Snapshot> snap;  // null until the first look is done

    std::string error, info;
    std::vector<std::string> notes;
    char name[64] = {}, address[1024] = {}, filter[64] = {}, paste[160] = {}, paste_name[64] = {};
    bool add_for_host = false, open_add = false;
    bool game_is_running = false;
    ULONGLONG running_checked = 0;

    // The one worker thread and what it shares with the window.
    std::mutex mutex;
    std::string status;                            // what the worker is doing, for the window
    std::deque<std::function<void(App&)>> done;    // what to do in the window's thread when it finishes
    bool busy = false;
    std::jthread worker;
};

void copy_text(char* buf, size_t size, std::string_view text) {
    const size_t n = std::min(size - 1, text.size());
    std::memcpy(buf, text.data(), n);
    buf[n] = 0;
}

// Runs `work(stop, status)` on the worker thread; what it returns runs in the window's thread afterwards.
template <class Work>
void start(App& app, Work work) {
    if (app.busy) return;
    app.busy = true;
    app.worker = std::jthread([&app, work = std::move(work)](std::stop_token stop) {
        const std::function<void(const std::string&)> status = [&app](const std::string& text) {
            const std::scoped_lock lock(app.mutex);
            app.status = text;
        };
        std::function<void(App&)> finish = work(stop, status);
        const std::scoped_lock lock(app.mutex);
        app.status.clear();
        app.done.push_back(std::move(finish));
    });
}

using Status = std::function<void(const std::string&)>;

// Looks at this PC again. `reload` = also Steam, the game and the packages (the update address is asked again);
// otherwise only what is in the game folder.
void refresh(App& app, bool reload) {
    const Paths paths = app.paths;
    const Settings settings = app.settings;
    const fs::path forced = app.forced_game_dir;
    const std::shared_ptr<const Snapshot> old = reload ? nullptr : app.snap;
    start(app, [=](std::stop_token stop, const Status& status) -> std::function<void(App&)> {
        auto snap = std::make_shared<Snapshot>();
        fs::path bin64 = paths.bin64;
        if (old) {
            *snap = *old;
        } else {
            status("Looking for Steam and the game...");
            snap->steam = read_steam();
            if (!forced.empty()) {
                bin64 = normalize_game_dir(forced);
            } else {
                bin64 = settings.game_dir.empty() ? fs::path() : normalize_game_dir(fs::path(widen(settings.game_dir)));
                if (bin64.empty()) bin64 = find_game(snap->steam.root);
            }
            snap->game = read_game(bin64);
            Paths look = paths;
            look.bin64 = bin64;
            status("Looking for the mod's files...");
            snap->catalog = load_catalog(look, settings, stop);
            if (snap->game.found) {
                const Choice choice = choose(snap->catalog, snap->game.pe.timestamp);
                if (choice.source) {
                    snap->chosen = static_cast<int>(choice.source - snap->catalog.sources.data());
                    snap->stated = choice.stated;
                }
            }
        }
        snap->folder = bin64.empty() ? FolderState{} : folder_state(bin64);
        return [snap, bin64](App& a) {
            a.snap = snap;
            a.paths.bin64 = bin64;
        };
    });
}

void save(App& app) { save_settings(app.paths, app.settings); }

// The Play button: make the game folder ready for the chosen way of playing, then start the game through Steam.
void play(App& app) {
    const std::shared_ptr<const Snapshot> snap = app.snap;
    if (!snap) return;
    app.error.clear();
    app.info.clear();
    app.notes.clear();
    app.settings.player_name = sanitize_player_name(app.name);
    copy_text(app.name, sizeof app.name, app.settings.player_name);
    save(app);

    ReadyRequest base;
    base.mode = app.settings.mode;
    base.player_name = app.settings.player_name;
    base.peer = base.mode == Mode::Join ? app.settings.join_host : base.mode == Mode::Host ? app.settings.host_accept : 0;
    base.recorded_loader = app.settings.installed_loader_sha256;
    const Paths paths = app.paths;
    const bool no_launch = app.no_launch;
    start(app, [=](std::stop_token stop, const Status& status) -> std::function<void(App&)> {
        ReadyRequest request = base;
        request.source = snap->source();
        request.status = status;
        const ReadyResult result = make_ready(paths, request, stop);
        std::string launch_error;
        bool launched = false;
        if (result.ok && !no_launch) {
            status("Starting the game through Steam...");
            launched = launch_game(&launch_error);
        }
        return [=](App& a) {
            a.notes = result.notes;
            if (!result.ok) {
                a.error = result.error;
            } else {
                a.settings.installed_loader_sha256 = result.recorded_loader;
                save(a);
                if (no_launch) {
                    a.info = "Ready. The game was not started (--no-launch).";
                } else if (launched) {
                    a.info = "Crimson Desert is starting through Steam.";
                } else {
                    a.error = launch_error;
                }
            }
            refresh(a, false);
        };
    });
}

std::optional<fs::path> pick_folder(HWND owner) {
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) {
        return std::nullopt;
    }
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dialog->SetTitle(L"Choose the Crimson Desert folder (the one that holds bin64)");
    std::optional<fs::path> out;
    IShellItem* item = nullptr;
    if (SUCCEEDED(dialog->Show(owner)) && SUCCEEDED(dialog->GetResult(&item)) && item) {
        PWSTR path = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
            out = fs::path(path);
            CoTaskMemFree(path);
        }
        item->Release();
    }
    dialog->Release();
    return out;
}

// ---------------------------------------------------------------- drawing
void wrapped(const std::string& text, const ImVec4* color = nullptr) {
    if (color) ImGui::PushStyleColor(ImGuiCol_Text, *color);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
    ImGui::PopTextWrapPos();
    if (color) ImGui::PopStyleColor();
}

std::string friend_label(const Settings& settings, uint64_t id) {
    const Contact* c = settings.friend_by_id(id);
    return c ? c->name : std::to_string(id);
}

void remember_friend(App& app, uint64_t id, std::string name) {
    if (!app.settings.friend_by_id(id)) {
        app.settings.friends.push_back({id, name.empty() ? std::to_string(id) : std::move(name)});
    }
    (app.add_for_host ? app.settings.host_accept : app.settings.join_host) = id;
    save(app);
}

bool contains_nocase(std::string_view text, std::string_view part) {
    if (part.empty()) return true;
    const auto it = std::search(text.begin(), text.end(), part.begin(), part.end(),
                                [](char a, char b) { return lower(a) == lower(b); });
    return it != text.end();
}

void add_friend_popup(App& app, const Snapshot& snap) {
    const float s = app.scale;
    if (app.open_add) {
        ImGui::OpenPopup("Add a friend");
        app.open_add = false;
        app.filter[0] = app.paste[0] = app.paste_name[0] = 0;
    }
    ImGui::SetNextWindowSize(ImVec2(520 * s, 0));
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Add a friend", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings)) {
        return;
    }
    wrapped("Pick a name Steam has saved on this PC. You must be Steam friends for the connection to work.");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##filter", "Search by name", app.filter, sizeof app.filter);
    ImGui::BeginChild("##contacts", ImVec2(0, 230 * s), ImGuiChildFlags_Borders);
    if (snap.steam.contacts.empty()) {
        wrapped("Steam's saved names were not found on this PC. Paste your friend's SteamID64 below instead.");
    }
    for (const Contact& c : snap.steam.contacts) {
        if (!contains_nocase(c.name, app.filter)) continue;
        ImGui::PushID(static_cast<int>(c.id & 0x7FFFFFFF));
        if (ImGui::Selectable(c.name.c_str())) {
            remember_friend(app, c.id, c.name);
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::Spacing();
    wrapped("Or paste their SteamID64 (17 digits) or their profile link:");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##paste", "7656119... or https://steamcommunity.com/profiles/7656119...", app.paste,
                             sizeof app.paste);
    const std::optional<uint64_t> pasted = parse_steamid(app.paste);
    if (app.paste[0] && !pasted) {
        wrapped("That is not a SteamID64. A link with a custom name (/id/...) does not contain it: ask your friend "
                "for the number this launcher shows them.", &kWarn);
    }
    ImGui::SetNextItemWidth(260 * s);
    ImGui::InputTextWithHint("##pastename", "Name (optional)", app.paste_name, sizeof app.paste_name);
    ImGui::SameLine();
    ImGui::BeginDisabled(!pasted);
    if (ImGui::Button("Add", ImVec2(90 * s, 0)) && pasted) {
        std::string name = clean_label(app.paste_name);
        if (name.empty()) {
            for (const Contact& c : snap.steam.contacts) {
                if (c.id == *pasted) name = c.name;
            }
        }
        remember_friend(app, *pasted, std::move(name));
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(90 * s, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// "Who": the first entry stands for nobody in particular (0), the rest are the friends picked before.
void friend_picker(App& app, const char* label, const char* nobody, uint64_t& value, bool for_host) {
    const float s = app.scale;
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(label);
    ImGui::SameLine(130 * s);
    ImGui::SetNextItemWidth(300 * s);
    const std::string preview = value ? friend_label(app.settings, value) : std::string(nobody);
    ImGui::PushID(label);
    if (ImGui::BeginCombo("##who", preview.c_str())) {
        if (ImGui::Selectable(nobody, value == 0)) value = 0, save(app);
        for (const Contact& c : app.settings.friends) {
            ImGui::PushID(static_cast<int>(c.id & 0x7FFFFFFF));
            if (ImGui::Selectable(c.name.c_str(), value == c.id)) value = c.id, save(app);
            ImGui::PopID();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button("Add a friend...")) {
        app.add_for_host = for_host;
        app.open_add = true;
    }
    if (value) {
        ImGui::SameLine();
        if (ImGui::Button("Forget")) {
            const uint64_t id = value;
            std::erase_if(app.settings.friends, [id](const Contact& c) { return c.id == id; });
            if (app.settings.join_host == id) app.settings.join_host = 0;
            if (app.settings.host_accept == id) app.settings.host_accept = 0;
            save(app);
        }
    }
    ImGui::PopID();
}

void own_id_line(const Snapshot& snap, const char* why) {
    if (!snap.steam.own_id) return;
    const std::string id = std::to_string(snap.steam.own_id);
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Your SteamID64: %s", id.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy")) ImGui::SetClipboardText(id.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("%s", why);
}

struct ModLine {
    std::string text;
    const ImVec4* color = nullptr;
    std::string detail;  // a second line, may be empty
    bool playable = false;  // Host and Join can go ahead
};

std::string game_version(const GameInfo& game) {
    if (!game.version.empty()) return game.version;
    char buf[32];
    std::snprintf(buf, sizeof buf, "build 0x%08X", game.pe.timestamp);
    return buf;
}

ModLine mod_line(const Snapshot& snap) {
    ModLine line;
    if (!snap.game.found) {
        line.text = "-";
        return line;
    }
    const Source* source = snap.source();
    if (!source) {
        line.color = &kWarn;
        if (snap.catalog.sources.empty()) {
            line.text = "The mod's files were not found.";
            line.detail = "Unzip the whole kit into one folder and start cdmp_launcher.exe from there.";
        } else {
            std::string made_for;
            for (const GameBuild& g : snap.catalog.sources.front().package.games) {
                made_for += (made_for.empty() ? "" : ", ") + g.version;
            }
            line.text = "No mod for game version " + game_version(snap.game) + " yet.";
            line.detail = "The mod here is for " + made_for + ". Steam has probably updated the game: you need a "
                          "new kit. Until then you can play single-player.";
        }
        if (snap.folder.asi) line.detail += " (The files of an earlier mod are in the game folder.)";
        return line;
    }
    line.playable = true;
    const PackageFile* asi = source->package.file(kFileAsi);
    const bool current = snap.folder.asi && asi && snap.folder.asi_sha256 == asi->sha256;
    line.text = source->package.id;
    if (current) {
        line.text += "  -  installed";
        line.color = &kGood;
    } else if (snap.folder.asi) {
        line.text += "  -  another version is installed: it is replaced when you play";
        line.color = &kWarn;
    } else {
        line.text += "  -  not in the game folder: it is installed when you play";
    }
    if (source->kind == Source::Kind::Update) line.detail = "From the update address.";
    if (!snap.stated) {
        line.detail = "This kit does not say which game version it is for. If the mod's panel does not appear in "
                      "the game, the kit is for another version.";
    }
    return line;
}

void mode_button(App& app, const char* label, Mode mode, float width) {
    const bool selected = app.settings.mode == mode;
    if (selected) {
        ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentActive);
    }
    if (ImGui::Button(label, ImVec2(width, 38 * app.scale)) && !selected) {
        app.settings.mode = mode;
        app.error.clear();
        app.info.clear();
        app.notes.clear();
        save(app);
    }
    if (selected) ImGui::PopStyleColor(3);
}

void draw(App& app) {
    const float s = app.scale;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::SetNextWindowSize(viewport->Size);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(26 * s, 20 * s));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin("##launcher", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::PopStyleVar(2);

    ImGui::PushFont(app.bold, 27.0f);
    ImGui::TextColored(kAccent, "Crimson Desert Multiplayer");
    ImGui::PopFont();
    const char* version = "launcher " CDMP_VERSION;
    ImGui::SameLine(ImGui::GetWindowWidth() - ImGui::CalcTextSize(version).x - 26 * s);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10 * s);
    ImGui::TextDisabled("%s", version);
    ImGui::Spacing();

    const std::shared_ptr<const Snapshot> held = app.snap;
    std::string status;
    {
        const std::scoped_lock lock(app.mutex);
        status = app.status;
    }
    if (!held) {
        ImGui::TextUnformatted(status.empty() ? "Looking for the game..." : status.c_str());
        ImGui::End();
        return;
    }
    const Snapshot& snap = *held;
    const ModLine mod = mod_line(snap);
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);

    // ---- what is on this PC
    if (ImGui::BeginTable("##found", 2)) {
        ImGui::TableSetupColumn("##what", ImGuiTableColumnFlags_WidthFixed, 64 * s);
        ImGui::TableSetupColumn("##value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextDisabled("Game");
        ImGui::TableNextColumn();
        if (snap.game.found) {
            ImGui::TextUnformatted(game_version(snap.game).c_str());
            ImGui::SameLine();
            wrapped(path_text(app.paths.bin64), &dim);
        } else {
            wrapped("Crimson Desert was not found. Choose its folder under \"Game folder and updates\" below.", &kWarn);
        }
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextDisabled("Mod");
        ImGui::TableNextColumn();
        wrapped(mod.text, mod.color);
        if (!mod.detail.empty()) wrapped(mod.detail, &dim);
        for (const std::string& note : snap.catalog.notes) wrapped(note, &kWarn);
        ImGui::EndTable();
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginDisabled(app.busy);

    // ---- who you are
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Your name");
    ImGui::SameLine(130 * s);
    ImGui::SetNextItemWidth(300 * s);
    ImGui::InputText("##name", app.name, sizeof app.name);
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        app.settings.player_name = sanitize_player_name(app.name);
        copy_text(app.name, sizeof app.name, app.settings.player_name);
        save(app);
    }
    ImGui::SameLine();
    ImGui::TextDisabled("the other player sees it (plain letters and digits)");
    ImGui::Spacing();

    // ---- how to play
    const float third = (ImGui::GetContentRegionAvail().x - 2 * ImGui::GetStyle().ItemSpacing.x) / 3;
    mode_button(app, "Join a friend", Mode::Join, third);
    ImGui::SameLine();
    mode_button(app, "Host a game", Mode::Host, third);
    ImGui::SameLine();
    mode_button(app, "Single-player", Mode::Single, third);

    ImGui::BeginChild("##mode", ImVec2(0, 186 * s), ImGuiChildFlags_Borders);
    switch (app.settings.mode) {
    case Mode::Join:
        wrapped("You play in your friend's world with your own character and save. Start once your friend is in "
                "their world, and press Play in the game's menu when the mod's panel says so.");
        ImGui::Spacing();
        friend_picker(app, "Join", "Automatic: the only friend playing", app.settings.join_host, false);
        if (app.settings.join_host == 0) {
            wrapped("Pick your friend by name if several friends play Crimson Desert or their profile hides it.", &dim);
        }
        own_id_line(snap, "(the host may need it)");
        break;
    case Mode::Host:
        wrapped("Your friend plays in your world. Start first and load your save; then your friend joins. When "
                "you finish, your friend leaves first.");
        ImGui::Spacing();
        friend_picker(app, "Who may join", "Any Steam friend who is playing", app.settings.host_accept, true);
        if (app.settings.host_accept == 0) {
            wrapped("Pick your friend by name if their Steam profile hides what they are playing.", &dim);
        }
        own_id_line(snap, "(send it to your friend if they cannot find you)");
        break;
    case Mode::Single:
        wrapped("The game starts without the mod: its files are taken out of the game folder, so the game runs "
                "exactly as Steam installed it. Your mod settings stay, and the mod comes back when you choose "
                "Join or Host here.");
        break;
    }
    ImGui::EndChild();
    ImGui::Spacing();

    // ---- play
    std::string blocker;
    if (!snap.game.found) {
        blocker = "The game was not found.";
    } else if (app.game_is_running) {
        blocker = "Crimson Desert is running. Close it to change how you play.";
    } else if (app.settings.mode != Mode::Single && !mod.playable) {
        blocker = "There is no mod for this game version here. You can still play single-player.";
    }
    std::string play_label = app.settings.mode == Mode::Single ? "Play without the mod"
                             : app.settings.mode == Mode::Host ? "Host a game"
                             : app.settings.join_host          ? "Join " + friend_label(app.settings, app.settings.join_host)
                                                               : "Join a friend";
    // A friend's name may need the fallback fonts, which only the regular face has.
    const bool ascii = std::all_of(play_label.begin(), play_label.end(), [](char c) { return c > 0; });
    play_label += "##play";
    ImGui::BeginDisabled(!blocker.empty());
    ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentActive);
    ImGui::PushFont(ascii ? app.bold : nullptr, 21.0f);
    const bool clicked = ImGui::Button(play_label.c_str(), ImVec2(-1, 52 * s));
    ImGui::PopFont();
    ImGui::PopStyleColor(3);
    ImGui::EndDisabled();
    if (clicked) play(app);

    ImGui::EndDisabled();  // busy

    // ---- what happened
    if (app.busy && !status.empty()) ImGui::TextUnformatted(status.c_str());
    if (!blocker.empty()) wrapped(blocker, &kWarn);
    if (!app.error.empty()) wrapped(app.error, &kBad);
    if (!app.info.empty()) wrapped(app.info, &kGood);
    for (const std::string& note : app.notes) wrapped(note, &kWarn);

    // ---- the rest
    ImGui::Spacing();
    ImGui::BeginDisabled(app.busy);
    if (ImGui::TreeNodeEx("Game folder and updates",
                          ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_NoTreePushOnOpen)) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Game folder");
        ImGui::SameLine(130 * s);
        if (ImGui::Button("Choose...")) {
            if (const auto picked = pick_folder(app.hwnd)) {
                const fs::path bin64 = normalize_game_dir(*picked);
                if (bin64.empty()) {
                    app.error = "CrimsonDesert.exe is not in that folder.";
                } else {
                    app.error.clear();
                    app.forced_game_dir.clear();
                    app.settings.game_dir = path_text(bin64);
                    save(app);
                    refresh(app, true);
                }
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Find it through Steam")) {
            app.forced_game_dir.clear();
            app.settings.game_dir.clear();
            save(app);
            refresh(app, true);
        }
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Updates from");
        ImGui::SameLine(130 * s);
        ImGui::SetNextItemWidth(410 * s);
        ImGui::InputTextWithHint("##address", "an https:// address or a shared folder (empty: this kit only)",
                                 app.address, sizeof app.address);
        ImGui::SameLine();
        if (ImGui::Button("Check now")) {
            app.settings.update_address = clean_label(app.address, 1024);
            save(app);
            refresh(app, true);
        }
        if (app.settings.update_address.empty() && !snap.catalog.update_address.empty()) {
            ImGui::TextDisabled("This kit checks %s", snap.catalog.update_address.c_str());
        }
    }
    ImGui::EndDisabled();

    add_friend_popup(app, snap);
    ImGui::End();
}

void apply_style(float scale) {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0;
    style.FrameRounding = 5;
    style.ChildRounding = 6;
    style.PopupRounding = 6;
    style.GrabRounding = 4;
    style.FramePadding = ImVec2(10, 6);
    style.ItemSpacing = ImVec2(9, 8);
    style.WindowPadding = ImVec2(16, 14);
    style.ChildBorderSize = 1;
    ImVec4* c = style.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(0.085f, 0.088f, 0.100f, 1);
    c[ImGuiCol_ChildBg] = ImVec4(0.115f, 0.120f, 0.135f, 1);
    c[ImGuiCol_PopupBg] = ImVec4(0.115f, 0.120f, 0.135f, 1);
    c[ImGuiCol_Border] = ImVec4(0.22f, 0.23f, 0.26f, 1);
    c[ImGuiCol_FrameBg] = ImVec4(0.17f, 0.18f, 0.20f, 1);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.22f, 0.23f, 0.26f, 1);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.26f, 0.27f, 0.30f, 1);
    c[ImGuiCol_Button] = ImVec4(0.20f, 0.21f, 0.24f, 1);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.27f, 0.28f, 0.32f, 1);
    c[ImGuiCol_ButtonActive] = ImVec4(0.32f, 0.33f, 0.37f, 1);
    c[ImGuiCol_Header] = ImVec4(0.20f, 0.21f, 0.24f, 1);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.27f, 0.28f, 0.32f, 1);
    c[ImGuiCol_HeaderActive] = ImVec4(0.32f, 0.33f, 0.37f, 1);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.17f, 0.18f, 0.20f, 1);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, 0.55f);
    c[ImGuiCol_TextDisabled] = ImVec4(0.58f, 0.60f, 0.64f, 1);
    style.ScaleAllSizes(scale);
    style.FontSizeBase = 17.0f;
    style.FontScaleDpi = scale;
}

// Segoe UI, with the symbol, Korean, Chinese and Japanese system fonts behind it for friends' names.
void load_fonts(App& app) {
    ImGuiIO& io = ImGui::GetIO();
    wchar_t windows[MAX_PATH] = {};
    GetWindowsDirectoryW(windows, MAX_PATH);
    const fs::path fonts = fs::path(windows) / L"Fonts";
    auto present = [&](const wchar_t* name) { return GetFileAttributesW((fonts / name).c_str()) != INVALID_FILE_ATTRIBUTES; };
    auto add = [&](const wchar_t* name, bool merge) -> ImFont* {
        if (!present(name)) return nullptr;
        ImFontConfig config;
        config.MergeMode = merge;
        return io.Fonts->AddFontFromFileTTF(path_text(fonts / name).c_str(), 0.0f, &config);
    };
    ImFont* regular = add(L"segoeui.ttf", false);
    if (!regular) regular = io.Fonts->AddFontDefault();
    for (const wchar_t* f : {L"seguisym.ttf", L"malgun.ttf", L"msyh.ttc", L"meiryo.ttc"}) add(f, true);
    // The bold face is only for the title and for labels in plain ASCII, so it needs no fallbacks.
    app.bold = add(L"segoeuib.ttf", false);
    if (!app.bold) app.bold = regular;
    io.FontDefault = regular;
}

void drain(App& app) {
    for (;;) {
        std::function<void(App&)> finish;
        {
            const std::scoped_lock lock(app.mutex);
            if (app.done.empty()) return;
            finish = std::move(app.done.front());
            app.done.pop_front();
        }
        app.busy = false;
        if (finish) finish(app);
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    App app;
    app.paths.data = default_data_dir();
    app.paths.bundle = exe_dir();
    bool own_data = true;
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        for (int i = 1; argv && i < argc; ++i) {
            const std::wstring_view arg = argv[i];
            const bool more = i + 1 < argc;
            if (arg == L"--no-launch") {
                app.no_launch = true;
            } else if (arg == L"--game-dir" && more) {
                app.forced_game_dir = argv[++i];
            } else if (arg == L"--data-dir" && more) {
                app.paths.data = argv[++i];
                own_data = false;
            } else if (arg == L"--bundle" && more) {
                app.paths.bundle = argv[++i];
            }
        }
        if (argv) LocalFree(argv);
    }

    // One launcher at a time (two would overwrite each other's settings): show the one already open.
    HANDLE single = nullptr;
    if (own_data) {
        single = CreateMutexW(nullptr, TRUE, L"Local\\cdmp_launcher_single");
        if (single && GetLastError() == ERROR_ALREADY_EXISTS) {
            if (const HWND other = FindWindowW(kWindowClass, nullptr)) {
                ShowWindow(other, SW_RESTORE);
                SetForegroundWindow(other);
            }
            return 0;
        }
    }

    (void)CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ImGui_ImplWin32_EnableDpiAwareness();
    const HMONITOR monitor = MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY);
    app.scale = ImGui_ImplWin32_GetDpiScaleForMonitor(monitor);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.lpszClassName = kWindowClass;
    RegisterClassExW(&wc);

    // A fixed-size window in the middle of the main screen.
    const DWORD window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT frame{0, 0, static_cast<LONG>(kWidth * app.scale), static_cast<LONG>(kHeight * app.scale)};
    AdjustWindowRectEx(&frame, window_style, FALSE, 0);
    MONITORINFO mi{};
    mi.cbSize = sizeof mi;
    GetMonitorInfoW(monitor, &mi);
    const int w = frame.right - frame.left, h = frame.bottom - frame.top;
    const int x = mi.rcWork.left + std::max(0L, ((mi.rcWork.right - mi.rcWork.left) - w) / 2);
    const int y = mi.rcWork.top + std::max(0L, ((mi.rcWork.bottom - mi.rcWork.top) - h) / 2);
    app.hwnd = CreateWindowExW(0, kWindowClass, L"Crimson Desert Multiplayer", window_style, x, y, w, h, nullptr,
                               nullptr, instance, nullptr);
    if (!app.hwnd || !create_device(app.hwnd)) {
        release_device();
        MessageBoxW(nullptr, L"The launcher could not open its window (Direct3D 11 is not available).",
                    L"Crimson Desert Multiplayer", MB_ICONERROR);
        return 1;
    }
    ShowWindow(app.hwnd, SW_SHOWDEFAULT);
    UpdateWindow(app.hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;  // the launcher keeps no window layout
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    apply_style(app.scale);
    ImGui_ImplWin32_Init(app.hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);
    load_fonts(app);

    app.settings = load_settings(app.paths);
    copy_text(app.name, sizeof app.name, app.settings.player_name);
    copy_text(app.address, sizeof app.address, app.settings.update_address);
    refresh(app, true);

    int frames_owed = 3;  // Dear ImGui needs a couple of frames to settle after any input
    for (bool quit = false; !quit;) {
        if (frames_owed <= 0) {
            MsgWaitForMultipleObjectsEx(0, nullptr, app.busy ? 30 : 150, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        }
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) quit = true;
            frames_owed = 3;
        }
        if (quit) break;
        if (g_occluded && g_swap_chain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            Sleep(50);
            drain(app);
            continue;
        }
        g_occluded = false;
        if (g_resize_width && g_resize_height) {
            release_target();
            g_swap_chain->ResizeBuffers(0, g_resize_width, g_resize_height, DXGI_FORMAT_UNKNOWN, 0);
            g_resize_width = g_resize_height = 0;
            create_target();
        }

        const bool was_busy = app.busy;
        drain(app);
        if (was_busy != app.busy) frames_owed = 3;
        if (const ULONGLONG now = GetTickCount64(); now - app.running_checked >= 1000) {
            app.running_checked = now;
            const bool running = game_running();
            if (running != app.game_is_running) frames_owed = 3;
            app.game_is_running = running;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        draw(app);
        ImGui::Render();
        const float clear[4] = {0.085f, 0.088f, 0.100f, 1.0f};
        g_context->OMSetRenderTargets(1, &g_target, nullptr);
        g_context->ClearRenderTargetView(g_target, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_occluded = g_swap_chain->Present(1, 0) == DXGI_STATUS_OCCLUDED;
        if (frames_owed > 0) --frames_owed;
    }

    app.worker.request_stop();
    if (app.worker.joinable()) app.worker.join();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    release_device();
    DestroyWindow(app.hwnd);
    UnregisterClassW(kWindowClass, instance);
    CoUninitialize();
    if (single) CloseHandle(single);
    return 0;
}
