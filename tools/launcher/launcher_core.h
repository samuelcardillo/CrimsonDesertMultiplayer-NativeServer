#pragma once
// The launcher's work on this PC, without a window: finding Steam and the game, reading the game's version, keeping
// a copy of each mod package, putting the mod into the game folder or taking it out, and starting the game. The
// rules are in launcher_logic.h; main.cpp is the window. Everything here can run on a worker thread.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include "launcher_logic.h"

namespace cdmp::launcher {

struct Paths {
    std::filesystem::path bin64;   // the game's folder with CrimsonDesert.exe (empty = not found)
    std::filesystem::path data;    // settings.ini and the copies of the packages
    std::filesystem::path bundle;  // the kit folder the launcher was started from
};

// ---- text and files
std::string narrow(std::wstring_view w);
std::wstring widen(std::string_view s);
std::string path_text(const std::filesystem::path& p);  // UTF-8, for the window
std::optional<std::vector<uint8_t>> read_file(const std::filesystem::path& p, size_t max_bytes);
std::optional<std::string> read_text(const std::filesystem::path& p, size_t max_bytes = size_t{16} << 20);
// Through a temporary file next to it, so a failure leaves the old file whole.
bool write_file(const std::filesystem::path& p, std::span<const uint8_t> data, std::string* error);
std::string sha256_of_file(const std::filesystem::path& p);  // empty = could not be read

// ---- Steam and the game
struct SteamInfo {
    std::filesystem::path root;     // empty = Steam is not installed for this Windows user
    uint64_t own_id = 0;            // the signed-in account, else the last one that signed in; 0 = none
    std::vector<Contact> contacts;  // the names Steam has cached for that account
};
SteamInfo read_steam();
// The bin64 of the Crimson Desert that Steam has installed; empty = none.
std::filesystem::path find_game(const std::filesystem::path& steam_root);
// A folder the player picked: bin64 itself or the game's folder above it. Empty = no CrimsonDesert.exe there.
std::filesystem::path normalize_game_dir(const std::filesystem::path& picked);

struct GameInfo {
    bool found = false;
    PeIdentity pe;
    std::string version;  // 1.0.0.3663; empty if the exe has no version resource
};
GameInfo read_game(const std::filesystem::path& bin64);
bool game_running();
FolderState folder_state(const std::filesystem::path& bin64);

// ---- packages
struct Source {
    enum class Kind { Update, Kit, Cache };
    Kind kind = Kind::Kit;
    Package package;
    std::string list;  // where the package's list is: its files are found from there (resolve_location)
};

struct Catalog {
    std::vector<Source> sources;     // in order of preference: the update address, the kit folder, earlier copies
    std::vector<std::string> notes;  // what could not be read, for the player
    std::string update_address;      // the one in use; empty = none set
    bool update_ok = false;          // the update address answered with a list
};

// The update address in the kit's own cdmp_launcher.ini ([update] address=), for players who set none.
std::string kit_update_address(const Paths& paths);
Catalog load_catalog(const Paths& paths, const Settings& settings, std::stop_token stop);

struct Choice {
    const Source* source = nullptr;
    bool stated = false;  // the package names this game build; false = a kit folder that does not say
};
Choice choose(const Catalog& catalog, uint32_t game_pe);

// ---- downloads (https only)
struct Download {
    bool ok = false;
    std::vector<uint8_t> body;
    std::string error;
};
Download http_get(const std::string& url, size_t max_bytes, std::stop_token stop,
                  const std::function<void(size_t done, size_t total)>& progress = {});

// ---- what the Play button does before the game starts
struct ReadyRequest {
    Mode mode = Mode::Single;
    std::string player_name;
    uint64_t peer = 0;                // Join: the host (0 = the only friend playing). Host: who may join (0 = any)
    const Source* source = nullptr;   // the package to play with; may be null for Mode::Single
    std::string recorded_loader;      // Settings::installed_loader_sha256
    std::function<bool()> game_is_running = game_running;
    std::function<void(const std::string&)> status;  // may be empty
};

struct ReadyResult {
    bool ok = false;
    std::string error;
    std::vector<std::string> notes;  // things the player should know that did not stop it
    std::string recorded_loader;     // the new Settings::installed_loader_sha256
};

// Single: the mod's files leave the game folder. Host / Join: the package is copied (downloaded if needed, every
// file checked against its SHA-256), installed, and cdmp.ini is written for that role. Nothing is written while the
// game runs. It never starts the game.
ReadyResult make_ready(const Paths& paths, const ReadyRequest& request, std::stop_token stop);

bool launch_game(std::string* error);  // through Steam: steam://rungameid/<app>

// ---- the launcher's settings (data\settings.ini)
Settings load_settings(const Paths& paths);
bool save_settings(const Paths& paths, const Settings& settings);
std::filesystem::path default_data_dir();  // %LOCALAPPDATA%\cdmp_launcher
std::filesystem::path exe_dir();

}  // namespace cdmp::launcher
