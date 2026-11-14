// The launcher (tools/launcher): its rules (launcher_logic.h) and its work on files (launcher_core.cpp) against fake
// kit, game and data folders in %TEMP%. Not tested here: the window, Steam's registry and the https download.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "common/sha256.h"
#include "launcher_core.h"

using namespace cdmp::launcher;
namespace fs = std::filesystem;

namespace {
int g_failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); ++g_failures; } } while (0)

constexpr uint32_t kPe = 0x6AF5D198, kOtherPe = 0x6AED2E85;
constexpr uint64_t kFriend = 76561198000000001ull, kFriend2 = 76561198000000002ull;

std::string sha(std::string_view s) {
    return cdmp::sha256::hex(cdmp::sha256::of({reinterpret_cast<const uint8_t*>(s.data()), s.size()}));
}

void put(const fs::path& p, std::string_view text) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary | std::ios::trunc).write(text.data(), static_cast<std::streamsize>(text.size()));
}

std::string get(const fs::path& p) { return read_text(p).value_or("<missing>"); }

// The first 4 KB of a 64-bit exe with that PE timestamp.
std::string fake_exe(uint32_t timestamp, uint32_t image_size = 0x144E9000) {
    std::string b(4096, '\0');
    auto u16 = [&](size_t o, uint32_t v) { b[o] = static_cast<char>(v), b[o + 1] = static_cast<char>(v >> 8); };
    auto u32 = [&](size_t o, uint32_t v) { u16(o, v), u16(o + 2, v >> 16); };
    b[0] = 'M', b[1] = 'Z';
    u32(0x3C, 0x80);
    u32(0x80, 0x00004550);
    u16(0x84, 0x8664);
    u32(0x88, timestamp);
    u16(0x80 + 24, 0x20B);
    u32(0x80 + 24 + 56, image_size);
    return b;
}

std::span<const uint8_t> bytes(const std::string& s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }

// ------------------------------------------------------------------ Steam's files
void test_vdf() {
    const auto libs = parse_vdf("\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n"
                                "\t\t\"apps\"\n\t\t{\n\t\t\t\"228980\"\t\t\"1\"\n\t\t}\n\t}\n"
                                "\t// a comment\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t}\n}\n");
    CHECK(libs.has_value());
    if (libs) {
        const auto paths = steam_library_paths(*libs);
        CHECK(paths.size() == 2);
        CHECK(paths.size() == 2 && paths[0] == "C:\\Program Files (x86)\\Steam" && paths[1] == "D:\\SteamLibrary");
    }
    const auto old = parse_vdf("\"LibraryFolders\" { \"TimeNextStatsReport\" \"1\" \"1\" \"E:\\\\Games\" }");
    CHECK(old && steam_library_paths(*old) == std::vector<std::string>{"E:\\Games"});
    const auto acf = parse_vdf("\"AppState\"\n{\n\t\"appid\"\t\"3321460\"\n\t\"installdir\"\t\"Crimson Desert\"\n}\n");
    CHECK(acf && app_install_dir(*acf) == "Crimson Desert");
    CHECK(!parse_vdf("\"a\" { \"b\" \"c\"").has_value());   // block not closed
    CHECK(!parse_vdf("\"a\" \"unterminated").has_value());
    CHECK(!parse_vdf("\"a\" }").has_value());
    CHECK(parse_vdf("").has_value());
}

void test_contacts() {
    const auto config = parse_vdf(R"("UserLocalConfigStore"
{
	"friends"
	{
		"PersonaName"		"Me"
		"40000002"
		{
			"name"		"zoe"
			"avatar"		"abc"
		}
		"40000001"
		{
			"name"		"Adam \"The\" Great"
			"NameHistory"
			{
				"0"		"Adam"
			}
		}
		"40000009"
		{
			"name"		"Me"
		}
		"40000003"
		{
			"avatar"		"no name here"
		}
	}
}
)");
    CHECK(config.has_value());
    if (!config) return;
    const auto contacts = contacts_from_localconfig(*config, 40000009);
    CHECK(contacts.size() == 2);
    if (contacts.size() == 2) {
        CHECK(contacts[0].name == "Adam \"The\" Great" && contacts[0].id == steamid_from_account(40000001));
        CHECK(contacts[1].name == "zoe" && contacts[1].id == 76561197960265728ull + 40000002);
    }
    const auto users = parse_vdf("\"users\" { \"76561198000000001\" { \"Timestamp\" \"100\" } "
                                 "\"76561198000000002\" { \"Timestamp\" \"200\" } }");
    CHECK(users && most_recent_login(*users) == kFriend2);
    const auto marked = parse_vdf("\"users\" { \"76561198000000001\" { \"MostRecent\" \"1\" \"Timestamp\" \"1\" } "
                                  "\"76561198000000002\" { \"Timestamp\" \"200\" } }");
    CHECK(marked && most_recent_login(*marked) == kFriend);
}

void test_steamid() {
    CHECK(parse_steamid("76561198000000001") == kFriend);
    CHECK(parse_steamid("  76561198000000001\r\n") == kFriend);
    CHECK(parse_steamid("https://steamcommunity.com/profiles/76561198000000001") == kFriend);
    CHECK(parse_steamid("https://steamcommunity.com/profiles/76561198000000001/friends?x=1") == kFriend);
    CHECK(!parse_steamid("https://steamcommunity.com/id/somebody"));
    CHECK(!parse_steamid("7656119800000000"));     // 16 digits
    CHECK(!parse_steamid("765611980000000012"));   // 18
    CHECK(!parse_steamid("12345678901234567"));    // not an individual account
    CHECK(!parse_steamid("76561197960265728"));    // account 0
    CHECK(!parse_steamid(""));
    CHECK(steamid_from_account(1) == 76561197960265729ull);
}

void test_pe() {
    const std::string exe = fake_exe(kPe);
    const auto id = pe_identity(bytes(exe));
    CHECK(id && id->timestamp == kPe && id->image_size == 0x144E9000);
    CHECK(!pe_identity(bytes(exe).first(0x90)));  // cut before the optional header
    std::string not_64 = exe;
    not_64[0x84] = 0x4C, not_64[0x85] = 0x01;
    CHECK(!pe_identity(bytes(not_64)));
    CHECK(!pe_identity(bytes(std::string(4096, 'x'))));
}

// ------------------------------------------------------------------ packages
const std::string kH1(64, 'a'), kH2(64, 'b'), kH3(64, 'c'), kH4(64, 'd');

std::string package_text(std::string_view id, std::string_view games) {
    return "[package]\nid=" + std::string(id) + "\n" + std::string(games) + "file=winmm.dll " + kH1 +
           "\nfile=cdmp.asi " + kH2 + " https://example.invalid/x/cdmp.asi\nfile=cdmp.ini.host " + kH3 +
           "\nfile=cdmp.ini.guest " + kH4 + "\nfile=README.txt " + kH1 + "\n";
}

void test_packages() {
    const std::string text = "; newest first\n" + package_text("v22", "game=1.0.0.3663 0x6AF5D198\ngame = 1.0.0.3576 0x6aed2e85\n") +
                             package_text("v21", "game=1.0.0.3576 0x6AED2E85\n");
    const PackageList list = parse_packages(text);
    CHECK(list.problems.empty());
    CHECK(list.packages.size() == 2);
    if (list.packages.size() == 2) {
        const Package& p = list.packages[0];
        CHECK(p.id == "v22" && p.games.size() == 2 && p.games[0].version == "1.0.0.3663" && p.games[0].pe == kPe);
        CHECK(p.supports(kPe) && p.supports(kOtherPe) && !p.supports(1));
        CHECK(p.files.size() == 4);  // README.txt is not something the launcher installs
        CHECK(p.file("cdmp.asi") && p.file("cdmp.asi")->where == "https://example.invalid/x/cdmp.asi");
        CHECK(p.file("winmm.dll") && p.file("winmm.dll")->where.empty());
        CHECK(!list.packages[1].supports(kPe));
        // What the launcher writes next to its copies reads back as the same package.
        const PackageList again = parse_packages(format_package(p));
        CHECK(again.packages.size() == 1 && again.problems.empty());
        CHECK(again.packages.size() == 1 && again.packages[0].games.size() == 2 && again.packages[0].supports(kPe) &&
              again.packages[0].file("cdmp.asi")->sha256 == kH2 && again.packages[0].file("cdmp.asi")->where.empty());
    }

    CHECK(parse_packages("[package]\nid=x\nfile=winmm.dll " + kH1 + "\n").packages.empty());           // three missing
    CHECK(parse_packages(package_text("../evil", "")).packages.empty());                               // a path as id
    CHECK(parse_packages(package_text("", "")).packages.empty());
    CHECK(parse_packages(package_text("ok", "game=1.0 nothex\n")).packages.empty());
    std::string bad_hash = package_text("ok", "");
    bad_hash.replace(bad_hash.find(kH2), 64, std::string(64, 'z'));
    CHECK(parse_packages(bad_hash).packages.empty() && !parse_packages(bad_hash).problems.empty());
    CHECK(parse_packages(package_text("ok", "") + "file=cdmp.asi " + kH2 + "\n").packages.empty());    // listed twice
    CHECK(parse_packages("").packages.empty() && parse_packages("").problems.empty());
    CHECK(valid_package_id("20261113-3663-v22") && !valid_package_id(".hidden") && !valid_package_id("a/b") &&
          !valid_package_id("a b") && !valid_package_id(std::string(65, 'a')));
    CHECK(normal_sha256(std::string(64, 'A')) == std::string(64, 'a') && normal_sha256("abc").empty());
}

void test_locations() {
    const std::string web = "https://host.example/mods/package.txt";
    CHECK(resolve_location(web, "", "cdmp.asi") == "https://host.example/mods/cdmp.asi");
    CHECK(resolve_location(web, "v22/cdmp.asi", "cdmp.asi") == "https://host.example/mods/v22/cdmp.asi");
    CHECK(resolve_location(web + "?token=1", "", "cdmp.asi") == "https://host.example/mods/cdmp.asi");
    CHECK(resolve_location(web, "https://cdn.example/a/cdmp.asi", "cdmp.asi") == "https://cdn.example/a/cdmp.asi");
    CHECK(resolve_location("https://host.example", "", "cdmp.asi") == "https://host.example/cdmp.asi");
    CHECK(resolve_location(web, "http://cdn.example/cdmp.asi", "cdmp.asi").empty());    // not https
    CHECK(resolve_location(web, "ftp://cdn.example/cdmp.asi", "cdmp.asi").empty());
    CHECK(resolve_location(web, "C:\\Windows\\cdmp.asi", "cdmp.asi").empty());          // a list on the network, a file here
    CHECK(resolve_location(web, "\\\\pc\\share\\cdmp.asi", "cdmp.asi").empty());
    CHECK(resolve_location(web, "/cdmp.asi", "cdmp.asi").empty());
    CHECK(resolve_location("D:\\kit\\package.txt", "", "cdmp.asi") == "D:\\kit\\cdmp.asi");
    CHECK(resolve_location("\\\\pc\\share\\package.txt", "v22\\cdmp.asi", "cdmp.asi") == "\\\\pc\\share\\v22\\cdmp.asi");
    CHECK(resolve_location("D:\\kit\\package.txt", "E:\\other\\cdmp.asi", "cdmp.asi") == "E:\\other\\cdmp.asi");
    CHECK(resolve_location("D:\\kit\\package.txt", "https://cdn.example/cdmp.asi", "x") == "https://cdn.example/cdmp.asi");
    CHECK(is_https("HTTPS://x.example/") && !is_https("http://x.example/") && !is_https("https://"));
}

// ------------------------------------------------------------------ ini text
void test_ini() {
    const std::string text = "; top\r\n[general]\r\nplayer_name=Player\r\n; note\r\nstartup_delay_ms=0\r\n\r\n"
                             "[Net]\r\nRole = guest\r\n;role=host\r\n\r\n[steam]\r\npeer_steamid=\r\n\r\n"
                             "[net]\r\nrole=second\r\n";
    CHECK(ini_get(text, "general", "player_name") == "Player");
    CHECK(ini_get(text, "GENERAL", "PLAYER_NAME") == "Player");
    CHECK(ini_get(text, "net", "role") == "guest");       // the first [net], and not the commented line
    CHECK(ini_get(text, "steam", "peer_steamid") == "");
    CHECK(!ini_get(text, "steam", "missing"));
    CHECK(!ini_get(text, "nowhere", "role"));

    // An existing key: only its line changes, and it keeps its spelling.
    const std::string renamed = ini_set(text, "general", "player_name", "Sam");
    CHECK(ini_get(renamed, "general", "player_name") == "Sam");
    CHECK(renamed.size() == text.size() - 3);
    CHECK(renamed.find("player_name=Sam\r\n; note\r\nstartup_delay_ms=0\r\n") != std::string::npos);
    const std::string role = ini_set(text, "net", "role", "host");
    CHECK(role.find("Role=host\r\n;role=host\r\n") != std::string::npos);
    CHECK(role.find("[net]\r\nrole=second\r\n") != std::string::npos);  // the second [net] is not read, so not written

    // A new key goes after the section's last line, before the blank line that ends it.
    const std::string added = ini_set(text, "general", "extra", "1");
    CHECK(added.find("startup_delay_ms=0\r\nextra=1\r\n\r\n[Net]") != std::string::npos);
    CHECK(ini_get(added, "general", "extra") == "1");
    // A new section goes at the end.
    const std::string section = ini_set(text, "launcher", "mode", "join");
    CHECK(section.ends_with("role=second\r\n\r\n[launcher]\r\nmode=join\r\n"));
    CHECK(ini_get(section, "launcher", "mode") == "join");
    // Line breaks stay as the file has them, and a last line without one gets one.
    CHECK(ini_set("[a]\nx=1\n", "a", "y", "2") == "[a]\nx=1\ny=2\n");
    CHECK(ini_set("[a]\nx=1", "a", "y", "2") == "[a]\nx=1\ny=2\n");
    CHECK(ini_set("", "a", "x", "1") == "[a]\r\nx=1\r\n");
    CHECK(ini_set("[a]\r\nx=1", "b", "y", "2") == "[a]\r\nx=1\r\n\r\n[b]\r\ny=2\r\n");

    const auto entries = ini_entries("[friends]\r\n1=a\r\n; no\r\n2 = b = c\r\n[other]\r\n3=d\r\n", "friends");
    CHECK(entries.size() == 2 && entries[0].first == "1" && entries[1].first == "2" && entries[1].second == "b = c");
}

void test_names() {
    CHECK(sanitize_player_name("  Sam  ") == "Sam");
    CHECK(sanitize_player_name("") == "Player");
    CHECK(sanitize_player_name("\"\"") == "Player");
    CHECK(sanitize_player_name("Sam\r\n[net]\r\nrole=host") == "Sam[net]role=host");  // one line, whatever is typed
    CHECK(sanitize_player_name("Jos\xC3\xA9") == "Jos");                                // the mod's reader is not UTF-8
    CHECK(sanitize_player_name(std::string(40, 'x')).size() == kMaxNameLen);
    CHECK(clean_label("a\tb\nc") == "abc");
    CHECK(clean_label("\xED\x95\x9C\xEA\xB8\x80", 4) == "\xED\x95\x9C");  // cut between characters, not inside one
}

// The mod's own reader on a file the launcher wrote.
std::string profile(const fs::path& ini, const wchar_t* section, const wchar_t* key) {
    wchar_t buf[256] = {};
    GetPrivateProfileStringW(section, key, L"<none>", buf, 256, ini.c_str());
    return narrow(buf);
}

void test_mod_ini(const fs::path& tmp) {
    const std::string source = CDMP_SOURCE_DIR;
    const std::string host = get(fs::path(source) / "kit" / "coop" / "cdmp.ini.host");
    const std::string guest = get(fs::path(source) / "kit" / "coop" / "cdmp.ini.guest");
    CHECK(host.size() > 1000 && guest.size() > 1000);
    const std::string hh = sha(host), gh = sha(guest);

    CHECK(!mod_ini("", host, hh, Role::Guest, "Sam", 0));  // the host's template is not a guest profile
    const auto fresh = mod_ini("", guest, gh, Role::Guest, "Sam", kFriend);
    CHECK(fresh && fresh->rewritten);
    if (!fresh) return;
    const auto marker = ini_marker(fresh->text);
    CHECK(marker && marker->role == "guest" && marker->template_sha256 == gh);
    CHECK(ini_get(fresh->text, "general", "player_name") == "Sam");
    CHECK(ini_get(fresh->text, "steam", "peer_steamid") == "76561198000000001");
    CHECK(ini_get(fresh->text, "net", "role") == "guest");
    // Apart from its three first lines and the two values, it is the kit's file byte for byte.
    size_t body = 0;
    for (int i = 0; i < 3; ++i) body = fresh->text.find('\n', body) + 1;
    CHECK(fresh->text.substr(body) ==
          ini_set(ini_set(guest, "general", "player_name", "Sam"), "steam", "peer_steamid", "76561198000000001"));

    // The game's reader sees the same values.
    const fs::path ini = tmp / "profile" / "cdmp.ini";
    put(ini, fresh->text);
    CHECK(profile(ini, L"general", L"player_name") == "Sam");
    CHECK(profile(ini, L"steam", L"peer_steamid") == "76561198000000001");
    CHECK(profile(ini, L"net", L"role") == "guest");
    CHECK(profile(ini, L"net", L"transport") == "steam");
    CHECK(profile(ini, L"session2", L"guest_shop_branch") == "5");

    // Same role, same template: the player's own change stays; only the two values move.
    const std::string tweaked = ini_set(fresh->text, "session2", "vehicle_follow", "0");
    const auto again = mod_ini(tweaked, guest, gh, Role::Guest, "Samuel", 0);
    CHECK(again && !again->rewritten);
    CHECK(again && ini_get(again->text, "session2", "vehicle_follow") == "0");
    CHECK(again && ini_get(again->text, "general", "player_name") == "Samuel");
    CHECK(again && ini_get(again->text, "steam", "peer_steamid") == "");
    // Nothing to change: the same text.
    const auto same = mod_ini(fresh->text, guest, gh, Role::Guest, "Sam", kFriend);
    CHECK(same && !same->rewritten && same->text == fresh->text);

    // Another template (a mod update) or another role: the kit's file again, without the change.
    const std::string updated = ini_set(guest, "session2", "new_setting", "1");
    const auto after_update = mod_ini(tweaked, updated, sha(updated), Role::Guest, "Sam", 0);
    CHECK(after_update && after_update->rewritten);
    CHECK(after_update && ini_get(after_update->text, "session2", "vehicle_follow") == "1");
    CHECK(after_update && ini_get(after_update->text, "session2", "new_setting") == "1");
    const auto as_host = mod_ini(tweaked, host, hh, Role::Host, "Sam", 0);
    CHECK(as_host && as_host->rewritten && ini_get(as_host->text, "net", "role") == "host");
    // A file whose role was changed by hand under the launcher's first line is not trusted.
    const auto edited = mod_ini(ini_set(fresh->text, "net", "role", "host"), guest, gh, Role::Guest, "Sam", 0);
    CHECK(edited && edited->rewritten && ini_get(edited->text, "net", "role") == "guest");
    // The player's own file from before the launcher has no first line of ours.
    CHECK(!ini_marker(guest));
    const auto over_own = mod_ini(guest, guest, gh, Role::Guest, "Sam", 0);
    CHECK(over_own && over_own->rewritten);
}

void test_plan() {
    const std::string asi = kH2, loader = kH1, old_loader = kH3, foreign = kH4;
    FolderState empty;
    SyncPlan p = plan_sync(true, empty, asi, loader, "");
    CHECK(p.copy_asi && p.copy_loader && !p.remove_asi && !p.remove_loader && !p.foreign_loader);

    FolderState installed{true, asi, true, loader, false};
    p = plan_sync(true, installed, asi, loader, "");
    CHECK(!p.changes() && !p.foreign_loader);
    p = plan_sync(false, installed, asi, loader, "");
    CHECK(p.remove_asi && p.remove_loader && !p.loader_kept);
    p = plan_sync(false, installed, "", "", loader);  // no package at hand: the recorded loader is still ours
    CHECK(p.remove_asi && p.remove_loader);
    p = plan_sync(false, installed, "", "", "");      // nothing says the loader is ours
    CHECK(p.remove_asi && !p.remove_loader && p.foreign_loader);

    FolderState old{true, kH4, true, old_loader, false};
    p = plan_sync(true, old, asi, loader, old_loader);  // an earlier package's files: both replaced
    CHECK(p.copy_asi && p.copy_loader && !p.foreign_loader);

    FolderState other{true, asi, true, foreign, false};
    p = plan_sync(true, other, asi, loader, old_loader);  // somebody else's winmm.dll
    CHECK(!p.copy_asi && !p.copy_loader && p.foreign_loader);
    p = plan_sync(false, other, asi, loader, old_loader);
    CHECK(p.remove_asi && !p.remove_loader && p.foreign_loader);

    FolderState shared{true, asi, true, loader, true};  // another mod's .asi needs the loader
    p = plan_sync(false, shared, asi, loader, "");
    CHECK(p.remove_asi && !p.remove_loader && p.loader_kept);

    FolderState nothing_of_ours{false, "", false, "", true};
    p = plan_sync(false, nothing_of_ours, asi, loader, "");
    CHECK(!p.changes());
}

void test_settings() {
    Settings s;
    s.game_dir = "D:\\Games\\Crimson Desert\\bin64";
    s.player_name = "Sam";
    s.mode = Mode::Host;
    s.join_host = kFriend;
    s.host_accept = kFriend2;
    s.update_address = "https://host.example/mods/";
    s.installed_loader_sha256 = kH1;
    s.friends = {{kFriend, "Adam = the first"}, {kFriend2, "\xED\x95\x9C\xEA\xB8\x80"}};
    const Settings r = parse_settings(format_settings(s));
    CHECK(r.game_dir == s.game_dir && r.player_name == "Sam" && r.mode == Mode::Host);
    CHECK(r.join_host == kFriend && r.host_accept == kFriend2 && r.update_address == s.update_address);
    CHECK(r.installed_loader_sha256 == kH1);
    CHECK(r.friends.size() == 2 && r.friends[0].name == "Adam = the first" && r.friends[1].id == kFriend2 &&
          r.friends[1].name == s.friends[1].name);
    const Settings d = parse_settings("garbage\n[launcher]\nmode=whatever\njoin_host=12\n[friends]\nabc=x\n12=y\n");
    CHECK(d.mode == Mode::Join && d.join_host == 0 && d.friends.empty() && d.player_name == "Player");
}

// ------------------------------------------------------------------ files
struct Kit {
    fs::path dir;
    std::string asi, loader;
};

// A kit folder as scripts/package_coop.ps1 makes it: the four files, and package.txt unless `listed` is false.
Kit make_kit(const fs::path& dir, std::string_view id, uint32_t pe, std::string_view tag, bool listed = true) {
    const std::string source = CDMP_SOURCE_DIR;
    Kit kit{dir, "asi of " + std::string(tag), "loader of " + std::string(tag)};
    const std::string host = get(fs::path(source) / "kit" / "coop" / "cdmp.ini.host");
    const std::string guest = get(fs::path(source) / "kit" / "coop" / "cdmp.ini.guest");
    put(dir / "cdmp.asi", kit.asi);
    put(dir / "winmm.dll", kit.loader);
    put(dir / "cdmp.ini.host", host);
    put(dir / "cdmp.ini.guest", guest);
    if (listed) {
        char game[64];
        std::snprintf(game, sizeof game, "game=1.0.0.9999 0x%08X\r\n", pe);
        put(dir / "package.txt", "[package]\r\nid=" + std::string(id) + "\r\n" + game + "file=winmm.dll " + sha(kit.loader) +
                                     "\r\nfile=cdmp.asi " + sha(kit.asi) + "\r\nfile=cdmp.ini.host " + sha(host) +
                                     "\r\nfile=cdmp.ini.guest " + sha(guest) + "\r\n");
    }
    return kit;
}

struct World {
    Paths paths;
    Settings settings;
    Catalog catalog;
    Choice choice;

    void look() {
        catalog = load_catalog(paths, settings, {});
        choice = choose(catalog, read_game(paths.bin64).pe.timestamp);
    }
    ReadyResult ready(Mode mode, uint64_t peer = 0, bool running = false) {
        ReadyRequest request;
        request.mode = mode;
        request.player_name = "Sam";
        request.peer = peer;
        request.source = choice.source;
        request.recorded_loader = settings.installed_loader_sha256;
        request.game_is_running = [running] { return running; };
        ReadyResult result = make_ready(paths, request, {});
        if (result.ok) settings.installed_loader_sha256 = result.recorded_loader;
        return result;
    }
};

World make_world(const fs::path& root) {
    World w;
    w.paths.bin64 = root / "game" / "bin64";
    w.paths.data = root / "data";
    w.paths.bundle = root / "kit";
    put(w.paths.bin64 / "CrimsonDesert.exe", fake_exe(kPe));
    return w;
}

void test_game_folder(const fs::path& tmp) {
    World w = make_world(tmp / "game_folder");
    const GameInfo game = read_game(w.paths.bin64);
    CHECK(game.found && game.pe.timestamp == kPe && game.version.empty());
    CHECK(!read_game(tmp / "nowhere").found);
    CHECK(normalize_game_dir(w.paths.bin64) == w.paths.bin64);
    CHECK(normalize_game_dir(w.paths.bin64.parent_path()) == w.paths.bin64);
    CHECK(normalize_game_dir(tmp).empty());
    put(w.paths.bin64 / "not_a_game.exe", "x");
    CHECK(!folder_state(w.paths.bin64).asi && !folder_state(w.paths.bin64).other_asi);
    put(w.paths.bin64 / "plugins" / "Other.ASI", "x");
    CHECK(folder_state(w.paths.bin64).other_asi);
}

void test_install_and_remove(const fs::path& tmp) {
    World w = make_world(tmp / "install");
    const Kit kit = make_kit(w.paths.bundle, "v1", kPe, "v1");
    w.look();
    CHECK(w.catalog.notes.empty());
    CHECK(w.choice.source && w.choice.stated && w.choice.source->kind == Source::Kind::Kit);
    if (!w.choice.source) return;

    // The game is running: nothing at all is written.
    ReadyResult r = w.ready(Mode::Join, kFriend, true);
    CHECK(!r.ok && !r.error.empty());
    CHECK(!fs::exists(w.paths.bin64 / "cdmp.asi") && !fs::exists(w.paths.data));

    // Join: the mod goes in and cdmp.ini is the guest's, with the name and the host.
    r = w.ready(Mode::Join, kFriend);
    CHECK(r.ok && r.error.empty() && r.notes.empty());
    CHECK(get(w.paths.bin64 / "cdmp.asi") == kit.asi && get(w.paths.bin64 / "winmm.dll") == kit.loader);
    const fs::path ini = w.paths.bin64 / "cdmp.ini";
    CHECK(ini_get(get(ini), "net", "role") == "guest" && ini_get(get(ini), "general", "player_name") == "Sam");
    CHECK(ini_get(get(ini), "steam", "peer_steamid") == "76561198000000001");
    CHECK(w.settings.installed_loader_sha256 == sha(kit.loader));
    CHECK(get(w.paths.data / "packages" / "v1" / "cdmp.asi") == kit.asi);
    CHECK(fs::exists(w.paths.data / "packages" / "v1" / "package.txt"));
    CHECK(!fs::exists(w.paths.bin64 / "cdmp.asi.cdmp-new") && !fs::exists(w.paths.bin64 / "cdmp.ini.bak"));

    // The player changes a setting; playing again as a guest keeps it.
    put(ini, ini_set(get(ini), "session2", "vehicle_follow", "0"));
    r = w.ready(Mode::Join, 0);
    CHECK(r.ok && ini_get(get(ini), "session2", "vehicle_follow") == "0" && ini_get(get(ini), "steam", "peer_steamid") == "");
    CHECK(!fs::exists(w.paths.bin64 / "cdmp.ini.bak"));

    // Hosting: the host's profile; the guest's file with that change is kept as cdmp.ini.bak.
    r = w.ready(Mode::Host, kFriend2);
    CHECK(r.ok && r.notes.size() == 1);
    CHECK(ini_get(get(ini), "net", "role") == "host" && ini_get(get(ini), "steam", "peer_steamid") == "76561198000000002");
    CHECK(ini_get(get(w.paths.bin64 / "cdmp.ini.bak"), "session2", "vehicle_follow") == "0");

    // Single-player: the game folder has nothing of the mod but its settings.
    r = w.ready(Mode::Single);
    CHECK(r.ok && r.notes.empty());
    CHECK(!fs::exists(w.paths.bin64 / "cdmp.asi") && !fs::exists(w.paths.bin64 / "winmm.dll") && fs::exists(ini));
    CHECK(fs::exists(w.paths.bin64 / "CrimsonDesert.exe"));
    r = w.ready(Mode::Single);  // and again: nothing to do
    CHECK(r.ok);

    // Without the kit folder the launcher's own copy is enough to play again.
    w.paths.bundle = tmp / "install" / "kit_was_deleted";
    w.look();
    CHECK(w.choice.source && w.choice.source->kind == Source::Kind::Cache && w.choice.stated);
    r = w.ready(Mode::Join);
    CHECK(r.ok && get(w.paths.bin64 / "cdmp.asi") == kit.asi && get(w.paths.bin64 / "winmm.dll") == kit.loader);
}

void test_other_peoples_files(const fs::path& tmp) {
    // Somebody else's winmm.dll is never replaced nor removed.
    World w = make_world(tmp / "foreign");
    const Kit kit = make_kit(w.paths.bundle, "v1", kPe, "v1");
    put(w.paths.bin64 / "winmm.dll", "another mod's loader");
    w.look();
    ReadyResult r = w.ready(Mode::Host);
    CHECK(r.ok && r.notes.size() == 1);
    CHECK(get(w.paths.bin64 / "winmm.dll") == "another mod's loader" && get(w.paths.bin64 / "cdmp.asi") == kit.asi);
    CHECK(w.settings.installed_loader_sha256.empty());
    r = w.ready(Mode::Single);
    CHECK(r.ok && get(w.paths.bin64 / "winmm.dll") == "another mod's loader" && !fs::exists(w.paths.bin64 / "cdmp.asi"));

    // Our loader stays while another mod's .asi needs it.
    World s = make_world(tmp / "shared");
    const Kit kit2 = make_kit(s.paths.bundle, "v1", kPe, "v1");
    put(s.paths.bin64 / "othermod.asi", "x");
    s.look();
    CHECK(s.ready(Mode::Join).ok);
    r = s.ready(Mode::Single);
    CHECK(r.ok && r.notes.size() == 1);
    CHECK(!fs::exists(s.paths.bin64 / "cdmp.asi") && get(s.paths.bin64 / "winmm.dll") == kit2.loader);
    CHECK(get(s.paths.bin64 / "othermod.asi") == "x");

    // The player's own cdmp.ini from before the launcher is kept once, and never overwritten afterwards.
    World o = make_world(tmp / "own_ini");
    make_kit(o.paths.bundle, "v1", kPe, "v1");
    put(o.paths.bin64 / "cdmp.ini", "[general]\r\nplayer_name=Mine\r\n[net]\r\nrole=guest\r\n");
    o.look();
    r = o.ready(Mode::Join);
    CHECK(r.ok && r.notes.size() == 1);
    CHECK(ini_get(get(o.paths.bin64 / "cdmp.ini.before-launcher"), "general", "player_name") == "Mine");
    CHECK(ini_marker(get(o.paths.bin64 / "cdmp.ini")).has_value());
    r = o.ready(Mode::Host);
    CHECK(r.ok && fs::exists(o.paths.bin64 / "cdmp.ini.bak"));
    CHECK(ini_get(get(o.paths.bin64 / "cdmp.ini.before-launcher"), "general", "player_name") == "Mine");
}

void test_bad_packages(const fs::path& tmp) {
    // A file that is not what the package says is not installed.
    World w = make_world(tmp / "tampered");
    make_kit(w.paths.bundle, "v1", kPe, "v1");
    put(w.paths.bundle / "cdmp.asi", "something else");
    w.look();
    CHECK(w.choice.source != nullptr);
    ReadyResult r = w.ready(Mode::Join);
    CHECK(!r.ok && r.error.find("cdmp.asi") != std::string::npos);
    CHECK(!fs::exists(w.paths.bin64 / "cdmp.asi") && !fs::exists(w.paths.bin64 / "winmm.dll") &&
          !fs::exists(w.paths.bin64 / "cdmp.ini"));
    CHECK(!fs::exists(w.paths.data / "packages" / "v1" / "cdmp.asi"));

    // A kit for another game build: no package to play with; single-player still works.
    World o = make_world(tmp / "other_build");
    make_kit(o.paths.bundle, "v0", kOtherPe, "v0");
    o.look();
    CHECK(!o.choice.source && o.catalog.sources.size() == 1);
    r = o.ready(Mode::Join);
    CHECK(!r.ok && !fs::exists(o.paths.bin64 / "cdmp.asi"));
    CHECK(o.ready(Mode::Single).ok);

    // A kit folder from before the launcher (no package.txt): usable, without a word on the game build.
    World u = make_world(tmp / "unlisted");
    const Kit kit = make_kit(u.paths.bundle, "", 0, "old", false);
    u.look();
    CHECK(u.choice.source && !u.choice.stated && u.choice.source->package.id.starts_with("kit-"));
    r = u.ready(Mode::Join);
    CHECK(r.ok && get(u.paths.bin64 / "cdmp.asi") == kit.asi);

    // No kit at all.
    World n = make_world(tmp / "no_kit");
    n.look();
    CHECK(!n.choice.source && n.catalog.sources.empty());
    CHECK(!n.ready(Mode::Host).ok && n.ready(Mode::Single).ok);
}

void test_update_address(const fs::path& tmp) {
    // The kit holds v1; the update address (a shared folder here) lists v2 for this game build: v2 is installed, and
    // then the earlier loader, which this launcher installed, is replaced too.
    World w = make_world(tmp / "update");
    const Kit v1 = make_kit(w.paths.bundle, "v1", kPe, "v1");
    w.look();
    CHECK(w.ready(Mode::Join).ok && get(w.paths.bin64 / "cdmp.asi") == v1.asi);

    const fs::path share = tmp / "update" / "share";
    const Kit v2 = make_kit(share, "v2", kPe, "v2");
    w.settings.update_address = path_text(share);  // a folder: its package.txt
    w.look();
    CHECK(w.catalog.update_ok && w.catalog.notes.empty());
    CHECK(w.choice.source && w.choice.source->kind == Source::Kind::Update && w.choice.source->package.id == "v2");
    ReadyResult r = w.ready(Mode::Join);
    CHECK(r.ok && get(w.paths.bin64 / "cdmp.asi") == v2.asi && get(w.paths.bin64 / "winmm.dll") == v2.loader);
    CHECK(w.settings.installed_loader_sha256 == sha(v2.loader));

    // The address does not answer: a note, and the kit's package is used.
    w.settings.update_address = path_text(tmp / "update" / "gone" / "package.txt");
    w.look();
    CHECK(!w.catalog.update_ok && w.catalog.notes.size() == 1);
    CHECK(w.choice.source && w.choice.source->kind == Source::Kind::Kit && w.choice.source->package.id == "v1");

    // The kit can carry the address for players who set none.
    put(w.paths.bundle / "cdmp_launcher.ini", "[update]\r\naddress=" + path_text(share / "package.txt") + "\r\n");
    w.settings.update_address.clear();
    w.look();
    CHECK(w.catalog.update_ok && w.choice.source && w.choice.source->package.id == "v2");

    // Only https is ever downloaded.
    CHECK(!http_get("http://example.invalid/package.txt", 1024, {}).ok);
    w.settings.update_address = "ftp://example.invalid/package.txt";
    w.look();
    CHECK(!w.catalog.update_ok && w.catalog.notes.size() == 1);

    Settings saved = w.settings;
    saved.friends = {{kFriend, "Adam"}};
    CHECK(save_settings(w.paths, saved));
    CHECK(load_settings(w.paths).friends.size() == 1 && load_settings(w.paths).update_address == saved.update_address);
}

}  // namespace

int main() {
    // Only this folder, made here, is removed at the end.
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    const fs::path tmp = fs::path(temp) / (L"cdmp_launcher_tests_" + std::to_wstring(GetCurrentProcessId()));
    std::error_code ec;
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp);

    test_vdf();
    test_contacts();
    test_steamid();
    test_pe();
    test_packages();
    test_locations();
    test_ini();
    test_names();
    test_mod_ini(tmp);
    test_plan();
    test_settings();
    test_game_folder(tmp);
    test_install_and_remove(tmp);
    test_other_peoples_files(tmp);
    test_bad_packages(tmp);
    test_update_address(tmp);

    fs::remove_all(tmp, ec);
    if (g_failures) {
        std::printf("%d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("launcher: ok\n");
    return 0;
}
