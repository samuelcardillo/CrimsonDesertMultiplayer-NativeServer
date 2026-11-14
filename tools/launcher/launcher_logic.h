#pragma once
// The launcher's rules, with no Windows calls (tests/launcher_tests.cpp): Steam's text files, the list of mod
// packages, the mod's ini and which files go into or out of the game folder. The files, the registry and the network
// are in launcher_core.cpp; the window is in main.cpp. docs/LAUNCHER.md.

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cdmp::launcher {

inline constexpr uint32_t kAppId = 3321460;
inline constexpr size_t kMaxNameLen = 32;  // proto::kMaxNameLen: what the other player's game accepts

// ------------------------------------------------------------------ text
inline char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; }

inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

inline std::string_view trim(std::string_view s) {
    auto blank = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && blank(s.front())) s.remove_prefix(1);
    while (!s.empty() && blank(s.back())) s.remove_suffix(1);
    return s;
}

inline bool all_digits(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

inline std::optional<uint64_t> parse_u64(std::string_view s, int base = 10) {
    uint64_t v = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (s.empty() || r.ec != std::errc() || r.ptr != s.data() + s.size()) return std::nullopt;
    return v;
}

// Words separated by spaces or tabs.
inline std::vector<std::string_view> words(std::string_view s) {
    std::vector<std::string_view> out;
    size_t at = 0;
    while (at < s.size()) {
        while (at < s.size() && (s[at] == ' ' || s[at] == '\t')) ++at;
        size_t end = at;
        while (end < s.size() && s[end] != ' ' && s[end] != '\t') ++end;
        if (end > at) out.push_back(s.substr(at, end - at));
        at = end;
    }
    return out;
}

// One line of text for a list or a settings file: no control characters, at most `max_bytes` of UTF-8 (never cut in
// the middle of a character).
inline std::string clean_label(std::string_view s, size_t max_bytes = 64) {
    std::string out;
    for (const char c : s) {
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) continue;
        out += c;
    }
    out = std::string(trim(out));
    if (out.size() > max_bytes) {
        size_t cut = max_bytes;
        while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80) --cut;
        out.resize(cut);
    }
    return out;
}

// ------------------------------------------------------------------ Valve's text KeyValues (.vdf, .acf)
struct VdfNode {
    std::string key;
    std::string value;              // a leaf's value
    std::vector<VdfNode> children;  // a block's entries
    bool block = false;

    const VdfNode* child(std::string_view name) const {
        for (const VdfNode& c : children) {
            if (iequals(c.key, name)) return &c;
        }
        return nullptr;
    }
    std::string_view leaf(std::string_view name) const {
        const VdfNode* c = child(name);
        return c && !c->block ? std::string_view(c->value) : std::string_view();
    }
};

namespace detail {

struct VdfReader {
    enum class Tok { End, Open, Close, Text, Bad };
    static constexpr int kMaxDepth = 64;
    static constexpr size_t kMaxNodes = 4'000'000;

    std::string_view s;
    size_t at = 0;
    size_t nodes = 0;

    Tok next(std::string& text) {
        for (;;) {
            while (at < s.size() && (s[at] == ' ' || s[at] == '\t' || s[at] == '\r' || s[at] == '\n')) ++at;
            if (at + 1 < s.size() && s[at] == '/' && s[at + 1] == '/') {
                while (at < s.size() && s[at] != '\n') ++at;
                continue;
            }
            break;
        }
        if (at >= s.size()) return Tok::End;
        const char c = s[at];
        if (c == '{') return ++at, Tok::Open;
        if (c == '}') return ++at, Tok::Close;
        text.clear();
        if (c == '"') {
            for (++at; at < s.size(); ++at) {
                if (s[at] == '"') return ++at, Tok::Text;
                if (s[at] == '\\' && at + 1 < s.size()) {
                    const char e = s[++at];
                    text += e == 'n' ? '\n' : e == 't' ? '\t' : e;
                    continue;
                }
                text += s[at];
            }
            return Tok::Bad;  // no closing quote
        }
        while (at < s.size() && s[at] != ' ' && s[at] != '\t' && s[at] != '\r' && s[at] != '\n' && s[at] != '{' &&
               s[at] != '}' && s[at] != '"') {
            text += s[at++];
        }
        return Tok::Text;
    }

    bool block(VdfNode& into, int depth) {
        if (depth > kMaxDepth) return false;
        std::string text;
        for (;;) {
            const Tok t = next(text);
            if (t == Tok::End) return depth == 0;
            if (t == Tok::Close) return depth > 0;
            if (t != Tok::Text || ++nodes > kMaxNodes) return false;
            VdfNode node;
            node.key = text;
            const Tok v = next(text);
            if (v == Tok::Open) {
                node.block = true;
                if (!block(node, depth + 1)) return false;
            } else if (v == Tok::Text) {
                node.value = text;
            } else {
                return false;
            }
            into.children.push_back(std::move(node));
        }
    }
};

}  // namespace detail

// The file's top-level entries as the children of a nameless block; nullopt if the text is not well formed.
inline std::optional<VdfNode> parse_vdf(std::string_view text) {
    if (text.starts_with("\xEF\xBB\xBF")) text.remove_prefix(3);
    detail::VdfReader reader{text};
    VdfNode root;
    root.block = true;
    if (!reader.block(root, 0)) return std::nullopt;
    return root;
}

// steamapps\libraryfolders.vdf: every library's folder (the new format's "path", or the old one's "1" "D:\\Lib").
inline std::vector<std::string> steam_library_paths(const VdfNode& root) {
    std::vector<std::string> out;
    const VdfNode* folders = root.child("libraryfolders");
    if (!folders) return out;
    for (const VdfNode& lib : folders->children) {
        if (lib.block) {
            const std::string_view path = lib.leaf("path");
            if (!path.empty()) out.emplace_back(path);
        } else if (all_digits(lib.key) && !lib.value.empty()) {
            out.push_back(lib.value);
        }
    }
    return out;
}

// appmanifest_<id>.acf: the game's folder name under steamapps\common.
inline std::string app_install_dir(const VdfNode& root) {
    const VdfNode* app = root.child("AppState");
    return app ? std::string(app->leaf("installdir")) : std::string();
}

// ------------------------------------------------------------------ SteamIDs
// An individual account in the public universe: what a Steam friend is.
inline constexpr uint64_t kSteamIdBase = 0x0110000100000000ull;
inline uint64_t steamid_from_account(uint32_t account) { return kSteamIdBase | account; }
inline bool valid_steamid(uint64_t id) { return (id >> 32) == (kSteamIdBase >> 32) && (id & 0xFFFFFFFFull) != 0; }

// What a player pastes: the 17 digits, or a profile link (.../profiles/7656119...). A link with a custom name
// (.../id/name) holds no SteamID: nullopt.
inline std::optional<uint64_t> parse_steamid(std::string_view input) {
    std::string_view s = trim(input);
    constexpr std::string_view kProfiles = "/profiles/";
    if (const size_t at = s.find(kProfiles); at != std::string_view::npos) {
        s.remove_prefix(at + kProfiles.size());
        const size_t end = s.find_first_of("/?#");
        if (end != std::string_view::npos) s = s.substr(0, end);
    }
    if (s.size() != 17 || !all_digits(s)) return std::nullopt;
    const auto id = parse_u64(s);
    return id && valid_steamid(*id) ? id : std::nullopt;
}

struct Contact {
    uint64_t id = 0;
    std::string name;
};

// userdata\<account>\config\localconfig.vdf: the names Steam has cached on this PC (friends, and sometimes people
// from group chats), without `own_account`. Sorted by name. Says nothing about who is playing.
inline std::vector<Contact> contacts_from_localconfig(const VdfNode& root, uint32_t own_account) {
    std::vector<Contact> out;
    const VdfNode* store = root.child("UserLocalConfigStore");
    const VdfNode* friends = store ? store->child("friends") : nullptr;
    if (!friends) return out;
    for (const VdfNode& f : friends->children) {
        if (!f.block || !all_digits(f.key)) continue;
        const auto account = parse_u64(f.key);
        if (!account || *account == 0 || *account > 0xFFFFFFFFull || *account == own_account) continue;
        std::string name = clean_label(f.leaf("name"));
        if (name.empty()) continue;
        out.push_back({steamid_from_account(static_cast<uint32_t>(*account)), std::move(name)});
    }
    std::sort(out.begin(), out.end(), [](const Contact& a, const Contact& b) {
        const bool less = std::lexicographical_compare(a.name.begin(), a.name.end(), b.name.begin(), b.name.end(),
                                                       [](char x, char y) { return lower(x) < lower(y); });
        if (less) return true;
        return iequals(a.name, b.name) && a.id < b.id;
    });
    return out;
}

// config\loginusers.vdf: the account that signed in last (0 = none), for when Steam is not running.
inline uint64_t most_recent_login(const VdfNode& root) {
    const VdfNode* users = root.child("users");
    if (!users) return 0;
    uint64_t best = 0, best_time = 0;
    for (const VdfNode& u : users->children) {
        const auto id = parse_u64(u.key);
        if (!u.block || !id || !valid_steamid(*id)) continue;
        if (u.leaf("MostRecent") == "1") return *id;
        const uint64_t time = parse_u64(u.leaf("Timestamp")).value_or(0);
        if (!best || time > best_time) best = *id, best_time = time;
    }
    return best;
}

// ------------------------------------------------------------------ the game's exe
struct PeIdentity {
    uint32_t timestamp = 0;
    uint32_t image_size = 0;
    bool operator==(const PeIdentity&) const = default;
};

// From the first bytes of the file (4 KB is plenty): the same two numbers the mod checks in memory.
inline std::optional<PeIdentity> pe_identity(std::span<const uint8_t> head) {
    auto u16 = [&](size_t o) { return static_cast<uint32_t>(head[o] | (head[o + 1] << 8)); };
    auto u32 = [&](size_t o) { return u16(o) | (u16(o + 2) << 16); };
    if (head.size() < 0x40 || head[0] != 'M' || head[1] != 'Z') return std::nullopt;
    const size_t nt = u32(0x3C);
    constexpr size_t kNeeded = 4 + 20 + 60;  // signature, file header, optional header up to SizeOfImage
    if (nt > head.size() || head.size() - nt < kNeeded) return std::nullopt;
    if (u32(nt) != 0x00004550 || u16(nt + 4) != 0x8664 || u16(nt + 24) != 0x20B) return std::nullopt;
    return PeIdentity{u32(nt + 8), u32(nt + 24 + 56)};
}

// ------------------------------------------------------------------ mod packages
// A package is one release of the mod: the four files the launcher installs, and the game builds it was made for.
// The same text describes a kit folder (package.txt next to the files) and an update address (a list, newest first):
//
//   [package]
//   id=20261113-3663-v22
//   game=1.0.0.3663 0x6AF5D198
//   file=winmm.dll <sha256> [where]
//   file=cdmp.asi <sha256> [where]
//   file=cdmp.ini.host <sha256> [where]
//   file=cdmp.ini.guest <sha256> [where]
//
// [where] is an https:// address or a path relative to the list; without it the file is next to the list.
inline constexpr std::string_view kFileLoader = "winmm.dll";
inline constexpr std::string_view kFileAsi = "cdmp.asi";
inline constexpr std::string_view kFileIniHost = "cdmp.ini.host";
inline constexpr std::string_view kFileIniGuest = "cdmp.ini.guest";
// The only names a package can make the launcher write.
inline constexpr std::string_view kPackageFiles[] = {kFileLoader, kFileAsi, kFileIniHost, kFileIniGuest};

struct PackageFile {
    std::string name;
    std::string sha256;  // 64 lower-case hex digits
    std::string where;   // may be empty
};

struct GameBuild {
    std::string version;  // as shown to the player: 1.0.0.3663
    uint32_t pe = 0;      // the exe's PE timestamp
};

struct Package {
    std::string id;
    std::vector<GameBuild> games;  // empty = not stated (a kit folder without package.txt)
    std::vector<PackageFile> files;

    const PackageFile* file(std::string_view name) const {
        for (const PackageFile& f : files) {
            if (f.name == name) return &f;
        }
        return nullptr;
    }
    bool supports(uint32_t pe) const {
        return std::any_of(games.begin(), games.end(), [pe](const GameBuild& g) { return g.pe == pe; });
    }
    bool complete() const {
        return std::all_of(std::begin(kPackageFiles), std::end(kPackageFiles),
                           [this](std::string_view n) { return file(n) != nullptr; });
    }
};

// Used as a folder name in the launcher's cache.
inline bool valid_package_id(std::string_view id) {
    auto alnum = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); };
    if (id.empty() || id.size() > 64 || !alnum(id.front())) return false;
    return std::all_of(id.begin(), id.end(), [&](char c) { return alnum(c) || c == '.' || c == '_' || c == '-'; });
}

// 64 hex digits in lower case; empty if `s` is not a SHA-256.
inline std::string normal_sha256(std::string_view s) {
    if (s.size() != 64) return {};
    std::string out;
    for (const char c : s) {
        const char l = lower(c);
        if (!((l >= '0' && l <= '9') || (l >= 'a' && l <= 'f'))) return {};
        out += l;
    }
    return out;
}

struct PackageList {
    std::vector<Package> packages;
    std::vector<std::string> problems;  // what was wrong with the packages left out
};

inline PackageList parse_packages(std::string_view text) {
    PackageList out;
    if (text.starts_with("\xEF\xBB\xBF")) text.remove_prefix(3);
    std::optional<Package> current;
    bool bad = false;
    auto problem = [&](std::string what) {
        out.problems.push_back((current && !current->id.empty() ? "package " + current->id + ": " : std::string()) +
                               std::move(what));
        bad = true;
    };
    auto flush = [&] {
        if (!current) return;
        if (!valid_package_id(current->id)) problem("no valid id");
        if (!current->complete()) problem("not all four files are listed");
        if (!bad) out.packages.push_back(std::move(*current));
        current.reset();
        bad = false;
    };
    size_t at = 0;
    while (at < text.size()) {
        size_t end = text.find('\n', at);
        if (end == std::string_view::npos) end = text.size();
        const std::string_view line = trim(text.substr(at, end - at));
        at = end + 1;
        if (line.empty() || line.front() == ';' || line.front() == '#') continue;
        if (iequals(line, "[package]")) {
            flush();
            current.emplace();
            continue;
        }
        const size_t eq = line.find('=');
        if (!current || eq == std::string_view::npos) continue;
        const std::string_view key = trim(line.substr(0, eq)), value = trim(line.substr(eq + 1));
        if (iequals(key, "id")) {
            current->id = std::string(value);
        } else if (iequals(key, "game")) {
            const auto w = words(value);
            std::optional<uint64_t> pe;
            if (w.size() == 2 && w[1].size() > 2 && (w[1].starts_with("0x") || w[1].starts_with("0X"))) {
                pe = parse_u64(w[1].substr(2), 16);
            }
            if (!pe || *pe == 0 || *pe > 0xFFFFFFFFull) {
                problem("bad game line '" + std::string(value) + "'");
            } else {
                current->games.push_back({clean_label(w[0], 32), static_cast<uint32_t>(*pe)});
            }
        } else if (iequals(key, "file")) {
            const auto w = words(value);
            if (w.size() < 2 || w.size() > 3) {
                problem("bad file line '" + std::string(value) + "'");
                continue;
            }
            if (std::find(std::begin(kPackageFiles), std::end(kPackageFiles), w[0]) == std::end(kPackageFiles)) {
                continue;  // a file this launcher does not install
            }
            std::string hash = normal_sha256(w[1]);
            if (hash.empty()) {
                problem("bad SHA-256 for " + std::string(w[0]));
            } else if (current->file(w[0])) {
                problem(std::string(w[0]) + " is listed twice");
            } else {
                current->files.push_back({std::string(w[0]), std::move(hash), w.size() == 3 ? std::string(w[2]) : ""});
            }
        }
    }
    flush();
    return out;
}

// One package as the text above, without [where]: what the launcher writes next to the files it has cached.
inline std::string format_package(const Package& p) {
    std::string out = "[package]\r\nid=" + p.id + "\r\n";
    for (const GameBuild& g : p.games) {
        char pe[16];
        const auto r = std::to_chars(pe, pe + sizeof pe, g.pe, 16);
        std::string hex(pe, r.ptr);
        for (char& c : hex) c = c >= 'a' && c <= 'f' ? static_cast<char>(c - 32) : c;
        out += "game=" + g.version + " 0x" + hex + "\r\n";
    }
    for (const PackageFile& f : p.files) out += "file=" + f.name + " " + f.sha256 + "\r\n";
    return out;
}

inline bool is_https(std::string_view s) { return s.size() > 8 && iequals(s.substr(0, 8), "https://"); }

// X:\... , X:/... or \\server\share.
inline bool is_absolute_local(std::string_view s) {
    if (s.size() >= 3 && ((lower(s[0]) >= 'a' && lower(s[0]) <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) {
        return true;
    }
    return s.starts_with("\\\\");
}

// Where a package's file is read from, given where the list is (an https:// address or a file's path) and the
// file's [where]. Empty = refused: anything remote must be https, and a list on the network cannot name a file on
// this PC.
inline std::string resolve_location(std::string_view list, std::string_view where, std::string_view file_name) {
    if (where.empty()) where = file_name;
    if (is_https(where)) return std::string(where);
    if (where.find("://") != std::string_view::npos) return {};
    if (is_https(list)) {
        if (is_absolute_local(where) || where.find('\\') != std::string_view::npos || where.starts_with("/")) return {};
        std::string_view base = list.substr(0, list.find_first_of("?#"));
        const size_t slash = base.rfind('/');
        if (slash == std::string_view::npos || slash < 8) return std::string(base) + "/" + std::string(where);
        return std::string(base.substr(0, slash + 1)) + std::string(where);
    }
    if (is_absolute_local(where)) return std::string(where);
    const size_t cut = list.find_last_of("\\/");
    if (cut == std::string_view::npos) return std::string(where);
    return std::string(list.substr(0, cut + 1)) + std::string(where);
}

// ------------------------------------------------------------------ ini text
// The same reading as GetPrivateProfileString (which the mod uses): the first section with that name, the first key
// with that name in it, names without regard to case, spaces around names and values dropped.
namespace detail {

struct IniLine {
    size_t begin = 0;  // of the line
    size_t end = 0;    // of its text, before the line break
    size_t next = 0;   // of the following line
};

template <class Fn>
void ini_lines(std::string_view text, Fn&& fn) {
    size_t at = 0;
    while (at < text.size()) {
        size_t nl = text.find('\n', at);
        IniLine line{at, nl == std::string_view::npos ? text.size() : nl,
                     nl == std::string_view::npos ? text.size() : nl + 1};
        if (line.end > line.begin && text[line.end - 1] == '\r') --line.end;
        std::string_view body = text.substr(line.begin, line.end - line.begin);
        if (at == 0 && body.starts_with("\xEF\xBB\xBF")) body.remove_prefix(3);
        at = line.next;
        if (!fn(line, trim(body))) return;
    }
}

inline std::optional<std::string_view> ini_section_name(std::string_view line) {
    if (line.empty() || line.front() != '[') return std::nullopt;
    const size_t close = line.find(']');
    if (close == std::string_view::npos) return std::nullopt;
    return trim(line.substr(1, close - 1));
}

inline std::string_view ini_eol(std::string_view text) {
    const size_t nl = text.find('\n');
    return nl != std::string_view::npos && (nl == 0 || text[nl - 1] != '\r') ? "\n" : "\r\n";
}

}  // namespace detail

inline std::optional<std::string> ini_get(std::string_view text, std::string_view section, std::string_view key) {
    std::optional<std::string> found;
    int state = 0;  // 0 before the section, 1 in it, 2 after it
    detail::ini_lines(text, [&](const detail::IniLine&, std::string_view line) {
        if (const auto name = detail::ini_section_name(line)) {
            if (state == 1) return false;
            if (iequals(*name, section)) state = 1;
            return true;
        }
        if (state != 1 || line.empty() || line.front() == ';') return true;
        const size_t eq = line.find('=');
        if (eq == std::string_view::npos || !iequals(trim(line.substr(0, eq)), key)) return true;
        found = std::string(trim(line.substr(eq + 1)));
        return false;
    });
    return found;
}

// Every key=value of the first section with that name, in order.
inline std::vector<std::pair<std::string, std::string>> ini_entries(std::string_view text, std::string_view section) {
    std::vector<std::pair<std::string, std::string>> out;
    int state = 0;
    detail::ini_lines(text, [&](const detail::IniLine&, std::string_view line) {
        if (const auto name = detail::ini_section_name(line)) {
            if (state == 1) return false;
            if (iequals(*name, section)) state = 1;
            return true;
        }
        if (state != 1 || line.empty() || line.front() == ';') return true;
        const size_t eq = line.find('=');
        if (eq == std::string_view::npos) return true;
        out.emplace_back(std::string(trim(line.substr(0, eq))), std::string(trim(line.substr(eq + 1))));
        return true;
    });
    return out;
}

// The text with that key set, and nothing else changed: the key's own line is rewritten; a missing key goes after the
// section's last line; a missing section goes at the end. The file's line breaks are kept.
inline std::string ini_set(std::string_view text, std::string_view section, std::string_view key,
                           std::string_view value) {
    const std::string_view eol = detail::ini_eol(text);
    int state = 0;
    std::optional<detail::IniLine> key_line;
    std::string key_spelling(key);
    size_t insert_at = std::string_view::npos;  // after the section's last line that is not blank
    detail::ini_lines(text, [&](const detail::IniLine& at, std::string_view line) {
        if (const auto name = detail::ini_section_name(line)) {
            if (state == 1) return false;
            if (iequals(*name, section)) {
                state = 1;
                insert_at = at.next;
            }
            return true;
        }
        if (state != 1) return true;
        if (!line.empty()) insert_at = at.next;
        if (line.empty() || line.front() == ';') return true;
        const size_t eq = line.find('=');
        if (eq == std::string_view::npos || !iequals(trim(line.substr(0, eq)), key)) return true;
        key_line = at;
        key_spelling = std::string(trim(line.substr(0, eq)));
        return false;
    });
    const std::string entry = key_spelling + "=" + std::string(value);
    std::string out;
    if (key_line) {
        out.append(text.substr(0, key_line->begin)).append(entry).append(text.substr(key_line->end));
        return out;
    }
    if (insert_at != std::string_view::npos) {
        out.append(text.substr(0, insert_at));
        if (!out.empty() && out.back() != '\n') out.append(eol);  // the section's last line had no line break
        out.append(entry).append(eol).append(text.substr(insert_at));
        return out;
    }
    out.append(text);
    if (!out.empty() && out.back() != '\n') out.append(eol);
    if (!out.empty()) out.append(eol);
    out.append("[").append(section).append("]").append(eol).append(entry).append(eol);
    return out;
}

// ------------------------------------------------------------------ the mod's cdmp.ini
enum class Role { Host, Guest };
inline std::string_view role_name(Role r) { return r == Role::Host ? "host" : "guest"; }
inline std::string_view role_template(Role r) { return r == Role::Host ? kFileIniHost : kFileIniGuest; }

// The mod reads its ini in the PC's ANSI code page, so only plain ASCII survives; quotes are dropped by that reader
// and a line break would start another line of the ini.
inline std::string sanitize_player_name(std::string_view name) {
    std::string out;
    for (const char c : name) {
        if (c >= 0x20 && c < 0x7F && c != '"' && c != '\'') out += c;
    }
    out = std::string(trim(out));
    if (out.size() > kMaxNameLen) out = std::string(trim(std::string_view(out).substr(0, kMaxNameLen)));
    return out.empty() ? "Player" : out;
}

// The first line of a cdmp.ini the launcher wrote: which role and which template it came from.
inline constexpr std::string_view kIniMarker = "; cdmp_launcher";
struct IniMarker {
    std::string role;
    std::string template_sha256;
};

inline std::optional<IniMarker> ini_marker(std::string_view text) {
    if (text.starts_with("\xEF\xBB\xBF")) text.remove_prefix(3);
    const std::string_view first = trim(text.substr(0, text.find('\n')));
    if (!first.starts_with(kIniMarker)) return std::nullopt;
    IniMarker m;
    for (const std::string_view w : words(first.substr(kIniMarker.size()))) {
        if (w.starts_with("role=")) m.role = std::string(w.substr(5));
        if (w.starts_with("template=")) m.template_sha256 = normal_sha256(w.substr(9));
    }
    if (m.role.empty() || m.template_sha256.empty()) return std::nullopt;
    return m;
}

struct ModIni {
    std::string text;
    bool rewritten = false;  // from the template; false = the existing file with only the two values changed
};

// The cdmp.ini to play as `role`. A file the launcher wrote for the same role from the same template keeps
// everything the player changed in it; anything else is replaced by the template, because the kit's settings are
// tested as a set and a file from another version may lack what the new mod needs.
// nullopt: `template_text` is not that role's template.
inline std::optional<ModIni> mod_ini(std::string_view existing, std::string_view template_text,
                                     std::string_view template_sha256, Role role, std::string_view player_name,
                                     uint64_t peer_steamid) {
    const auto template_role = ini_get(template_text, "net", "role");
    if (!template_role || !iequals(*template_role, role_name(role))) return std::nullopt;
    const auto marker = ini_marker(existing);
    const auto existing_role = ini_get(existing, "net", "role");
    const bool keep = marker && marker->role == role_name(role) && marker->template_sha256 == template_sha256 &&
                      existing_role && iequals(*existing_role, role_name(role));
    ModIni out;
    out.rewritten = !keep;
    if (keep) {
        out.text = std::string(existing);
    } else {
        const std::string_view eol = detail::ini_eol(template_text);
        out.text.append(kIniMarker).append(" role=").append(role_name(role)).append(" template=")
            .append(template_sha256).append(eol)
            .append("; Written by cdmp_launcher, which sets your name and who you play with. Other changes you make")
            .append(eol)
            .append("; in this file are kept until the mod is updated or you switch between hosting and joining.")
            .append(eol).append(template_text);
    }
    out.text = ini_set(out.text, "general", "player_name", sanitize_player_name(player_name));
    out.text = ini_set(out.text, "steam", "peer_steamid", peer_steamid ? std::to_string(peer_steamid) : "");
    return out;
}

// ------------------------------------------------------------------ the game folder
// What is in bin64 now.
struct FolderState {
    bool asi = false;
    std::string asi_sha256;
    bool loader = false;
    std::string loader_sha256;
    bool other_asi = false;  // an .asi that is not ours: another mod that needs a loader
};

struct SyncPlan {
    bool copy_asi = false;
    bool remove_asi = false;
    bool copy_loader = false;
    bool remove_loader = false;
    bool foreign_loader = false;  // a winmm.dll that is not ours: never touched
    bool loader_kept = false;     // ours, left in place for another mod's .asi
    bool changes() const { return copy_asi || remove_asi || copy_loader || remove_loader; }
};

// With the mod (`mod_on`): cdmp.asi and the loader are the package's. Without it: both are gone, so the game runs
// as Steam installed it. A winmm.dll is ours only if it is the package's file or the one this launcher installed
// before (`recorded_loader`); any other is somebody else's and stays as it is.
inline SyncPlan plan_sync(bool mod_on, const FolderState& now, std::string_view package_asi,
                          std::string_view package_loader, std::string_view recorded_loader) {
    SyncPlan plan;
    const bool ours = now.loader && ((!package_loader.empty() && now.loader_sha256 == package_loader) ||
                                     (!recorded_loader.empty() && now.loader_sha256 == recorded_loader));
    plan.foreign_loader = now.loader && !ours;
    if (mod_on) {
        plan.copy_asi = !now.asi || now.asi_sha256 != package_asi;
        plan.copy_loader = !now.loader || (ours && now.loader_sha256 != package_loader);
    } else {
        plan.remove_asi = now.asi;
        plan.loader_kept = ours && now.other_asi;
        plan.remove_loader = ours && !now.other_asi;
    }
    return plan;
}

// ------------------------------------------------------------------ the launcher's own settings
enum class Mode { Single, Host, Join };
inline std::string_view mode_name(Mode m) { return m == Mode::Single ? "single" : m == Mode::Host ? "host" : "join"; }

struct Settings {
    std::string game_dir;                  // empty = found through Steam
    std::string player_name = "Player";
    Mode mode = Mode::Join;
    uint64_t join_host = 0;                // 0 = the only friend playing
    uint64_t host_accept = 0;              // 0 = any friend who is playing
    std::string update_address;            // empty = the kit's (cdmp_launcher.ini), if it has one
    std::string installed_loader_sha256;   // the winmm.dll this launcher put in the game folder
    std::vector<Contact> friends;          // the people the player has picked before

    const Contact* friend_by_id(uint64_t id) const {
        for (const Contact& c : friends) {
            if (c.id == id) return &c;
        }
        return nullptr;
    }
};

inline Settings parse_settings(std::string_view text) {
    Settings s;
    auto get = [&](std::string_view key) { return ini_get(text, "launcher", key).value_or(""); };
    s.game_dir = clean_label(get("game_dir"), 1024);
    s.player_name = sanitize_player_name(get("player_name"));
    const std::string mode = get("mode");
    s.mode = iequals(mode, "single") ? Mode::Single : iequals(mode, "host") ? Mode::Host : Mode::Join;
    auto id = [&](std::string_view key) {
        const auto v = parse_u64(get(key));
        return v && valid_steamid(*v) ? *v : 0;
    };
    s.join_host = id("join_host");
    s.host_accept = id("host_accept");
    s.update_address = clean_label(get("update_address"), 1024);
    s.installed_loader_sha256 = normal_sha256(get("installed_loader_sha256"));
    for (const auto& [key, value] : ini_entries(text, "friends")) {
        const auto fid = parse_u64(key);
        if (!fid || !valid_steamid(*fid) || s.friend_by_id(*fid)) continue;
        std::string name = clean_label(value);
        s.friends.push_back({*fid, name.empty() ? key : std::move(name)});
    }
    return s;
}

inline std::string format_settings(const Settings& s) {
    std::string out = "[launcher]\r\n";
    auto line = [&](std::string_view key, std::string_view value) {
        out.append(key).append("=").append(value).append("\r\n");
    };
    line("game_dir", clean_label(s.game_dir, 1024));
    line("player_name", sanitize_player_name(s.player_name));
    line("mode", mode_name(s.mode));
    line("join_host", std::to_string(s.join_host));
    line("host_accept", std::to_string(s.host_accept));
    line("update_address", clean_label(s.update_address, 1024));
    line("installed_loader_sha256", s.installed_loader_sha256);
    out += "\r\n[friends]\r\n";
    for (const Contact& c : s.friends) line(std::to_string(c.id), clean_label(c.name));
    return out;
}

}  // namespace cdmp::launcher
