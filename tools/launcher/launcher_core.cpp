#include "launcher_core.h"

#include <windows.h>

#include <shellapi.h>
#include <tlhelp32.h>
#include <winhttp.h>

#include <algorithm>
#include <cstdio>
#include <system_error>
#include <utility>

#include "common/sha256.h"

namespace cdmp::launcher {
namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxListBytes = size_t{1} << 20;
constexpr size_t kMaxFileBytes = size_t{128} << 20;  // cdmp.asi is about 16 MB
constexpr wchar_t kExeName[] = L"CrimsonDesert.exe";

std::string error_text(DWORD code) {
    wchar_t buf[512] = {};
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0, buf,
                                   ARRAYSIZE(buf), nullptr);
    std::string text = narrow(std::wstring_view(buf, n));
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ' || text.back() == '.')) {
        text.pop_back();
    }
    return text.empty() ? "error " + std::to_string(code) : text;
}

struct File {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~File() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    explicit operator bool() const { return h != INVALID_HANDLE_VALUE; }
};

File open_for_reading(const fs::path& p) {
    // Shared with everything, so the game's exe can be read while the game runs.
    return File{CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
}

bool file_exists(const fs::path& p) {
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool is_dir(const fs::path& p) {
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

std::optional<std::wstring> reg_string(HKEY root, const wchar_t* key, const wchar_t* value) {
    wchar_t buf[1024] = {};
    DWORD size = sizeof buf - sizeof(wchar_t);
    if (RegGetValueW(root, key, value, RRF_RT_REG_SZ, nullptr, buf, &size) != ERROR_SUCCESS) return std::nullopt;
    return std::wstring(buf);
}

std::optional<DWORD> reg_dword(HKEY root, const wchar_t* key, const wchar_t* value) {
    DWORD v = 0, size = sizeof v;
    if (RegGetValueW(root, key, value, RRF_RT_REG_DWORD, nullptr, &v, &size) != ERROR_SUCCESS) return std::nullopt;
    return v;
}

std::optional<VdfNode> read_vdf(const fs::path& p, size_t max_bytes) {
    const auto text = read_text(p, max_bytes);
    return text ? parse_vdf(*text) : std::nullopt;
}

bool is_asi(const fs::path& p) { return iequals(narrow(p.extension().wstring()), ".asi"); }

struct InternetHandle {
    HINTERNET h = nullptr;
    ~InternetHandle() {
        if (h) WinHttpCloseHandle(h);
    }
    explicit operator bool() const { return h != nullptr; }
};

std::span<const uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

std::string megabytes(size_t bytes) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.1f", static_cast<double>(bytes) / (1024.0 * 1024.0));
    return buf;
}

// The update address as the place of a package list: a folder (or an address ending in /) means its package.txt.
std::string list_address(std::string address) {
    if (is_https(address)) {
        if (address.back() == '/') address += "package.txt";
    } else if (address.find("://") == std::string::npos && is_dir(fs::path(widen(address)))) {
        if (address.back() != '\\' && address.back() != '/') address += '\\';
        address += "package.txt";
    }
    return address;
}

struct ListText {
    std::optional<std::string> text;
    std::string error;
};

ListText read_list(const std::string& address, std::stop_token stop) {
    if (is_https(address)) {
        Download d = http_get(address, kMaxListBytes, stop);
        if (!d.ok) return {std::nullopt, d.error};
        return {std::string(d.body.begin(), d.body.end()), {}};
    }
    if (address.find("://") != std::string::npos) return {std::nullopt, "only https:// addresses and folders are read"};
    auto text = read_text(fs::path(widen(address)), kMaxListBytes);
    if (!text) return {std::nullopt, "the file could not be read"};
    return {std::move(text), {}};
}

fs::path cache_dir(const Paths& paths, const Package& package) {
    return paths.data / L"packages" / widen(package.id);
}

// Every file of the package in the launcher's own folder, each checked against its SHA-256. Files already there
// with the right hash are not fetched again.
bool ensure_cached(const Paths& paths, const Source& source, const ReadyRequest& request, std::stop_token stop,
                   std::string& error) {
    const fs::path dir = cache_dir(paths, source.package);
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        error = "Could not create " + path_text(dir) + " (" + ec.message() + ").";
        return false;
    }
    for (const PackageFile& file : source.package.files) {
        const fs::path target = dir / widen(file.name);
        if (sha256_of_file(target) == file.sha256) continue;
        if (source.kind == Source::Kind::Cache) {
            error = "The launcher's copy of " + file.name + " is damaged. Get the mod's files again.";
            return false;
        }
        const std::string from = resolve_location(source.list, file.where, file.name);
        if (from.empty()) {
            error = "The package lists " + file.name + " at a place the launcher does not read.";
            return false;
        }
        std::vector<uint8_t> data;
        if (is_https(from)) {
            Download d = http_get(from, kMaxFileBytes, stop, [&](size_t done, size_t total) {
                if (!request.status) return;
                request.status("Downloading " + file.name + " (" + megabytes(done) +
                               (total ? " of " + megabytes(total) : std::string()) + " MB)...");
            });
            if (!d.ok) {
                error = "Could not download " + file.name + " (" + d.error + ").";
                return false;
            }
            data = std::move(d.body);
        } else {
            auto read = read_file(fs::path(widen(from)), kMaxFileBytes);
            if (!read) {
                error = "Could not read " + from + ".";
                return false;
            }
            data = std::move(*read);
        }
        if (sha256::hex(sha256::of(data)) != file.sha256) {
            error = file.name + " does not match the package's checksum, so it was not installed.";
            return false;
        }
        std::string why;
        if (!write_file(target, data, &why)) {
            error = "Could not save " + file.name + " (" + why + ").";
            return false;
        }
    }
    if (source.kind != Source::Kind::Cache) {
        const std::string text = format_package(source.package);
        std::string why;
        if (!write_file(dir / L"package.txt", bytes_of(text), &why)) {
            error = "Could not save the package's list (" + why + ").";
            return false;
        }
    }
    return true;
}

// A checked copy of one cached file into the game folder.
bool install_file(const fs::path& cache, const fs::path& bin64, const PackageFile& file, std::string& error) {
    const auto data = read_file(cache / widen(file.name), kMaxFileBytes);
    if (!data || sha256::hex(sha256::of(*data)) != file.sha256) {
        error = "The launcher's copy of " + file.name + " is damaged.";
        return false;
    }
    std::string why;
    if (!write_file(bin64 / widen(file.name), *data, &why)) {
        error = "Could not write " + file.name + " in the game folder (" + why + ").";
        return false;
    }
    return true;
}

bool remove_file(const fs::path& p, std::string& error) {
    if (DeleteFileW(p.c_str())) return true;
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND) return true;
    error = "Could not remove " + path_text(p.filename()) + " from the game folder (" + error_text(code) + ").";
    return false;
}

}  // namespace

// ------------------------------------------------------------------ text and files
std::string narrow(std::wstring_view w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string path_text(const fs::path& p) { return narrow(p.wstring()); }

std::optional<std::vector<uint8_t>> read_file(const fs::path& p, size_t max_bytes) {
    const File f = open_for_reading(p);
    LARGE_INTEGER size{};
    if (!f || !GetFileSizeEx(f.h, &size) || static_cast<uint64_t>(size.QuadPart) > max_bytes) return std::nullopt;
    std::vector<uint8_t> data(static_cast<size_t>(size.QuadPart));
    size_t at = 0;
    while (at < data.size()) {
        const DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - at, size_t{1} << 24));
        DWORD got = 0;
        if (!ReadFile(f.h, data.data() + at, want, &got, nullptr) || got == 0) return std::nullopt;
        at += got;
    }
    return data;
}

std::optional<std::string> read_text(const fs::path& p, size_t max_bytes) {
    const auto data = read_file(p, max_bytes);
    if (!data) return std::nullopt;
    return std::string(data->begin(), data->end());
}

bool write_file(const fs::path& p, std::span<const uint8_t> data, std::string* error) {
    auto fail = [&](DWORD code) {
        if (error) *error = error_text(code);
        return false;
    };
    fs::path tmp = p;
    tmp += L".cdmp-new";
    DWORD code = ERROR_SUCCESS;
    {
        const File f{CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (!f) return fail(GetLastError());
        size_t at = 0;
        while (at < data.size() && code == ERROR_SUCCESS) {
            const DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - at, size_t{1} << 24));
            DWORD wrote = 0;
            if (!WriteFile(f.h, data.data() + at, want, &wrote, nullptr)) {
                code = GetLastError();
            } else if (wrote == 0) {
                code = ERROR_WRITE_FAULT;
            }
            at += wrote;
        }
        if (code == ERROR_SUCCESS && !FlushFileBuffers(f.h)) code = GetLastError();
    }
    if (code == ERROR_SUCCESS && !MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        code = GetLastError();
    }
    if (code != ERROR_SUCCESS) {
        DeleteFileW(tmp.c_str());
        return fail(code);
    }
    return true;
}

std::string sha256_of_file(const fs::path& p) {
    const File f = open_for_reading(p);
    if (!f) return {};
    sha256::Hasher hasher;
    std::vector<uint8_t> buf(size_t{1} << 20);
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(f.h, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) return {};
        if (got == 0) break;
        hasher.update(std::span<const uint8_t>(buf.data(), got));
    }
    return sha256::hex(hasher.finish());
}

// ------------------------------------------------------------------ Steam and the game
SteamInfo read_steam() {
    SteamInfo info;
    auto root = reg_string(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath");
    if (!root || root->empty()) {
        root = reg_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath");
    }
    if (!root || root->empty()) return info;
    fs::path path(*root);
    path.make_preferred();
    if (!is_dir(path)) return info;
    info.root = path;

    // The account signed in now; with Steam closed, the one that signed in last.
    uint32_t account = reg_dword(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\ActiveProcess", L"ActiveUser").value_or(0);
    if (!account) {
        if (const auto users = read_vdf(path / L"config" / L"loginusers.vdf", size_t{4} << 20)) {
            account = static_cast<uint32_t>(most_recent_login(*users) & 0xFFFFFFFFull);
        }
    }
    if (!account) return info;
    info.own_id = steamid_from_account(account);
    const fs::path local = path / L"userdata" / std::to_wstring(account) / L"config" / L"localconfig.vdf";
    if (const auto config = read_vdf(local, size_t{64} << 20)) {
        info.contacts = contacts_from_localconfig(*config, account);
    }
    return info;
}

fs::path find_game(const fs::path& steam_root) {
    if (steam_root.empty()) return {};
    std::vector<fs::path> libraries{steam_root};
    if (const auto folders = read_vdf(steam_root / L"steamapps" / L"libraryfolders.vdf", size_t{4} << 20)) {
        for (const std::string& lib : steam_library_paths(*folders)) libraries.emplace_back(widen(lib));
    }
    const std::wstring manifest = L"appmanifest_" + std::to_wstring(kAppId) + L".acf";
    for (const fs::path& lib : libraries) {
        const fs::path apps = lib / L"steamapps";
        const auto acf = read_vdf(apps / manifest, size_t{1} << 20);
        if (!acf) continue;
        std::string dir = app_install_dir(*acf);
        if (dir.empty()) dir = "Crimson Desert";
        const fs::path bin64 = apps / L"common" / widen(dir) / L"bin64";
        if (file_exists(bin64 / kExeName)) return bin64;
    }
    return {};
}

fs::path normalize_game_dir(const fs::path& picked) {
    if (picked.empty()) return {};
    if (file_exists(picked / kExeName)) return picked;
    if (file_exists(picked / L"bin64" / kExeName)) return picked / L"bin64";
    return {};
}

GameInfo read_game(const fs::path& bin64) {
    GameInfo info;
    if (bin64.empty()) return info;
    const fs::path exe = bin64 / kExeName;
    {
        const File f = open_for_reading(exe);
        if (!f) return info;
        uint8_t head[4096];
        DWORD got = 0;
        if (!ReadFile(f.h, head, sizeof head, &got, nullptr)) return info;
        const auto pe = pe_identity(std::span<const uint8_t>(head, got));
        if (!pe) return info;
        info.pe = *pe;
        info.found = true;
    }
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(exe.c_str(), &ignored);
    if (size) {
        std::vector<uint8_t> block(size);
        VS_FIXEDFILEINFO* fixed = nullptr;
        UINT len = 0;
        if (GetFileVersionInfoW(exe.c_str(), 0, size, block.data()) &&
            VerQueryValueW(block.data(), L"\\", reinterpret_cast<void**>(&fixed), &len) && fixed &&
            len >= sizeof *fixed) {
            info.version = std::to_string(HIWORD(fixed->dwFileVersionMS)) + "." +
                           std::to_string(LOWORD(fixed->dwFileVersionMS)) + "." +
                           std::to_string(HIWORD(fixed->dwFileVersionLS)) + "." +
                           std::to_string(LOWORD(fixed->dwFileVersionLS));
        }
    }
    return info;
}

bool game_running() {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof entry;
    bool found = false;
    for (BOOL ok = Process32FirstW(snap, &entry); ok && !found; ok = Process32NextW(snap, &entry)) {
        found = _wcsicmp(entry.szExeFile, kExeName) == 0;
    }
    CloseHandle(snap);
    return found;
}

FolderState folder_state(const fs::path& bin64) {
    FolderState state;
    const fs::path asi = bin64 / widen(kFileAsi), loader = bin64 / widen(kFileLoader);
    if (file_exists(asi)) {
        state.asi = true;
        state.asi_sha256 = sha256_of_file(asi);
    }
    if (file_exists(loader)) {
        state.loader = true;
        state.loader_sha256 = sha256_of_file(loader);
    }
    // Where Ultimate ASI Loader looks for mods: next to the exe, scripts\ and plugins\.
    for (const fs::path& dir : {bin64, bin64 / L"scripts", bin64 / L"plugins"}) {
        std::error_code ec;
        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
            if (!is_asi(it->path())) continue;
            if (dir == bin64 && iequals(narrow(it->path().filename().wstring()), kFileAsi)) continue;
            state.other_asi = true;
        }
    }
    return state;
}

// ------------------------------------------------------------------ packages
std::string kit_update_address(const Paths& paths) {
    if (paths.bundle.empty()) return {};
    const auto text = read_text(paths.bundle / L"cdmp_launcher.ini", kMaxListBytes);
    return text ? clean_label(ini_get(*text, "update", "address").value_or(""), 1024) : std::string();
}

Catalog load_catalog(const Paths& paths, const Settings& settings, std::stop_token stop) {
    Catalog catalog;
    catalog.update_address = settings.update_address.empty() ? kit_update_address(paths) : settings.update_address;
    if (!catalog.update_address.empty()) {
        const std::string list = list_address(catalog.update_address);
        ListText text = read_list(list, stop);
        if (!text.text) {
            catalog.notes.push_back("Could not check for updates (" + text.error + ").");
        } else {
            PackageList parsed = parse_packages(*text.text);
            for (const std::string& p : parsed.problems) catalog.notes.push_back("Update list: " + p + ".");
            if (parsed.packages.empty()) catalog.notes.push_back("The update address lists no usable package.");
            catalog.update_ok = !parsed.packages.empty();
            for (Package& p : parsed.packages) {
                catalog.sources.push_back({Source::Kind::Update, std::move(p), list});
            }
        }
    }

    if (!paths.bundle.empty()) {
        const fs::path list = paths.bundle / L"package.txt";
        if (const auto text = read_text(list, kMaxListBytes)) {
            PackageList parsed = parse_packages(*text);
            for (const std::string& p : parsed.problems) catalog.notes.push_back("This kit's package.txt: " + p + ".");
            for (Package& p : parsed.packages) {
                catalog.sources.push_back({Source::Kind::Kit, std::move(p), path_text(list)});
            }
        } else {
            // A kit folder from before the launcher: the four files, with no word on which game build they are for.
            Package p;
            for (const std::string_view name : kPackageFiles) {
                std::string hash = sha256_of_file(paths.bundle / widen(name));
                if (!hash.empty()) p.files.push_back({std::string(name), std::move(hash), {}});
            }
            if (p.complete()) {
                p.id = "kit-" + p.file(kFileAsi)->sha256.substr(0, 12);
                catalog.sources.push_back({Source::Kind::Kit, std::move(p), path_text(list)});
            }
        }
    }

    // Packages copied earlier, newest first: they keep the launcher working without the kit folder.
    struct Cached {
        fs::file_time_type time;
        Source source;
    };
    std::vector<Cached> cached;
    std::error_code ec;
    for (fs::directory_iterator it(paths.data / L"packages", ec), end; !ec && it != end; it.increment(ec)) {
        const fs::path list = it->path() / L"package.txt";
        const auto text = read_text(list, kMaxListBytes);
        if (!text) continue;
        PackageList parsed = parse_packages(*text);
        if (parsed.packages.size() != 1 || widen(parsed.packages[0].id) != it->path().filename().wstring()) continue;
        std::error_code time_ec;
        cached.push_back({fs::last_write_time(list, time_ec),
                          {Source::Kind::Cache, std::move(parsed.packages[0]), path_text(list)}});
    }
    std::stable_sort(cached.begin(), cached.end(), [](const Cached& a, const Cached& b) { return a.time > b.time; });
    for (Cached& c : cached) catalog.sources.push_back(std::move(c.source));
    return catalog;
}

Choice choose(const Catalog& catalog, uint32_t game_pe) {
    for (const Source& s : catalog.sources) {
        if (s.package.supports(game_pe)) return {&s, true};
    }
    for (const Source& s : catalog.sources) {
        if (s.package.games.empty()) return {&s, false};
    }
    return {};
}

// ------------------------------------------------------------------ downloads
Download http_get(const std::string& url, size_t max_bytes, std::stop_token stop,
                  const std::function<void(size_t, size_t)>& progress) {
    Download out;
    auto fail = [&](std::string what) {
        out.error = std::move(what);
        out.body.clear();
    };
    if (!is_https(url)) return fail("only https:// addresses are downloaded"), out;
    const std::wstring wide = widen(url);
    wchar_t host[256] = {}, path[2048] = {}, extra[2048] = {};
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof parts;
    parts.lpszHostName = host;
    parts.dwHostNameLength = ARRAYSIZE(host);
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = ARRAYSIZE(path);
    parts.lpszExtraInfo = extra;
    parts.dwExtraInfoLength = ARRAYSIZE(extra);
    if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts) ||
        parts.nScheme != INTERNET_SCHEME_HTTPS) {
        return fail("the address is not valid"), out;
    }
    std::wstring object = std::wstring(path) + extra;
    if (const size_t hash = object.find(L'#'); hash != std::wstring::npos) object.resize(hash);
    if (object.empty()) object = L"/";

    // A generic client name: nothing about the player or the PC goes in the request.
    const InternetHandle session{WinHttpOpen(L"cdmp-launcher", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session) return fail(error_text(GetLastError())), out;
    WinHttpSetTimeouts(session.h, 10000, 10000, 20000, 30000);
    const InternetHandle connection{WinHttpConnect(session.h, host, parts.nPort, 0)};
    if (!connection) return fail(error_text(GetLastError())), out;
    const InternetHandle request{WinHttpOpenRequest(connection.h, L"GET", object.c_str(), nullptr, WINHTTP_NO_REFERER,
                                                    WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)};
    if (!request) return fail(error_text(GetLastError())), out;
    if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.h, nullptr)) {
        return fail("no answer from " + narrow(host) + " (error " + std::to_string(GetLastError()) + ")"), out;
    }
    DWORD status = 0, size = sizeof status;
    WinHttpQueryHeaders(request.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &size, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) return fail("the server answered " + std::to_string(status)), out;
    DWORD length = 0;
    size = sizeof length;
    const size_t total =
        WinHttpQueryHeaders(request.h, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &length, &size, WINHTTP_NO_HEADER_INDEX)
            ? length
            : 0;
    if (total > max_bytes) return fail("the file is larger than expected"), out;
    for (;;) {
        if (stop.stop_requested()) return fail("cancelled"), out;
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.h, &available)) return fail(error_text(GetLastError())), out;
        if (!available) break;
        if (out.body.size() + available > max_bytes) return fail("the file is larger than expected"), out;
        const size_t at = out.body.size();
        out.body.resize(at + available);
        DWORD got = 0;
        if (!WinHttpReadData(request.h, out.body.data() + at, available, &got)) {
            return fail(error_text(GetLastError())), out;
        }
        out.body.resize(at + got);
        if (!got) break;
        if (progress) progress(out.body.size(), total);
    }
    if (total && out.body.size() != total) return fail("the download stopped early"), out;
    out.ok = true;
    return out;
}

// ------------------------------------------------------------------ before the game starts
ReadyResult make_ready(const Paths& paths, const ReadyRequest& request, std::stop_token stop) {
    ReadyResult result;
    result.recorded_loader = request.recorded_loader;
    auto status = [&](const std::string& text) {
        if (request.status) request.status(text);
    };
    auto fail = [&](std::string why) {
        result.error = std::move(why);
        return result;
    };
    if (paths.bin64.empty() || !file_exists(paths.bin64 / kExeName)) return fail("The game folder was not found.");
    if (request.game_is_running && request.game_is_running()) {
        return fail("Crimson Desert is running. Close it first: its files cannot be changed while it runs.");
    }
    const bool mod_on = request.mode != Mode::Single;
    const Package* package = request.source ? &request.source->package : nullptr;
    if (mod_on && !package) return fail("There is no mod package to install.");

    std::string error;
    if (mod_on) {
        status("Getting the mod's files...");
        if (!ensure_cached(paths, *request.source, request, stop, error)) return fail(error);
    }

    status("Checking the game folder...");
    const FolderState now = folder_state(paths.bin64);
    const std::string package_asi = package && package->file(kFileAsi) ? package->file(kFileAsi)->sha256 : "";
    const std::string package_loader = package && package->file(kFileLoader) ? package->file(kFileLoader)->sha256 : "";
    const SyncPlan plan = plan_sync(mod_on, now, package_asi, package_loader, request.recorded_loader);

    if (!mod_on) {
        if (plan.changes()) status("Taking the mod out of the game folder...");
        if (plan.remove_asi && !remove_file(paths.bin64 / widen(kFileAsi), error)) return fail(error);
        if (plan.remove_loader && !remove_file(paths.bin64 / widen(kFileLoader), error)) return fail(error);
        if (plan.loader_kept) {
            result.notes.push_back("The mod's loader (winmm.dll) stays in the game folder: another .asi mod there needs it.");
        }
        result.ok = true;
        return result;
    }

    const fs::path cache = cache_dir(paths, *package);
    if (plan.changes()) status("Installing the mod...");
    if (plan.copy_loader && !install_file(cache, paths.bin64, *package->file(kFileLoader), error)) return fail(error);
    if (plan.copy_asi && !install_file(cache, paths.bin64, *package->file(kFileAsi), error)) return fail(error);
    if (plan.foreign_loader) {
        result.notes.push_back("A winmm.dll that is not the mod's was already in the game folder and was left as it is. "
                               "The mod only loads if that file is an ASI loader.");
    } else {
        result.recorded_loader = package_loader;
    }

    status("Writing your settings...");
    const Role role = request.mode == Mode::Host ? Role::Host : Role::Guest;
    const PackageFile& template_file = *package->file(role_template(role));
    const auto template_text = read_text(cache / widen(template_file.name));
    if (!template_text) return fail("The launcher's copy of " + template_file.name + " could not be read.");
    const fs::path ini = paths.bin64 / L"cdmp.ini";
    const std::string existing = read_text(ini).value_or("");
    const auto made = mod_ini(existing, *template_text, template_file.sha256, role, request.player_name, request.peer);
    if (!made) return fail("The package's " + template_file.name + " is not a " + std::string(role_name(role)) + " profile.");
    if (made->rewritten && !existing.empty()) {
        // The player's own file from before the launcher is kept once and never overwritten; a file the launcher
        // wrote (with the player's later changes) goes to cdmp.ini.bak.
        const bool own = !ini_marker(existing).has_value();
        const fs::path backup = paths.bin64 / (own ? L"cdmp.ini.before-launcher" : L"cdmp.ini.bak");
        if (!own || !file_exists(backup)) {
            std::string why;
            if (!write_file(backup, bytes_of(existing), &why)) {
                return fail("Could not save a copy of your cdmp.ini (" + why + ").");
            }
            result.notes.push_back("Your previous cdmp.ini was saved as " + path_text(backup.filename()) + ".");
        }
    }
    if (made->text != existing) {
        std::string why;
        if (!write_file(ini, bytes_of(made->text), &why)) {
            return fail("Could not write cdmp.ini in the game folder (" + why + ").");
        }
    }
    result.ok = true;
    return result;
}

bool launch_game(std::string* error) {
    const std::wstring url = L"steam://rungameid/" + std::to_wstring(kAppId);
    const auto code =
        reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    if (code > 32) return true;
    if (error) *error = "Steam did not take the request to start the game. Is Steam installed?";
    return false;
}

// ------------------------------------------------------------------ settings
Settings load_settings(const Paths& paths) {
    const auto text = read_text(paths.data / L"settings.ini", kMaxListBytes);
    return text ? parse_settings(*text) : Settings{};
}

bool save_settings(const Paths& paths, const Settings& settings) {
    std::error_code ec;
    fs::create_directories(paths.data, ec);
    const std::string text = format_settings(settings);
    return write_file(paths.data / L"settings.ini", bytes_of(text), nullptr);
}

fs::path default_data_dir() {
    wchar_t local[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return exe_dir() / L"cdmp_launcher_data";
    return fs::path(local) / L"cdmp_launcher";
}

fs::path exe_dir() {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    return fs::path(buf).parent_path();
}

}  // namespace cdmp::launcher
