// updatecore.cpp — see updatecore.h.
#include "updatecore.h"
#include "version.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace nv {

// ---------------------------------------------------------------- versions

static bool ParseUInt(const std::string& s, unsigned maxDigits, unsigned long long& out)
{
    if (s.empty() || s.size() > maxDigits) return false;
    if (s.size() > 1 && s[0] == '0') return false;          // no leading zeros
    unsigned long long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (unsigned)(c - '0');
    }
    out = v;
    return true;
}

bool ParseVersion(const std::string& s, Version& out)
{
    size_t d1 = s.find('.');
    if (d1 == std::string::npos) return false;
    size_t d2 = s.find('.', d1 + 1);
    if (d2 == std::string::npos || s.find('.', d2 + 1) != std::string::npos) return false;
    unsigned long long a = 0, b = 0, c = 0;
    if (!ParseUInt(s.substr(0, d1), 4, a) ||
        !ParseUInt(s.substr(d1 + 1, d2 - d1 - 1), 4, b) ||
        !ParseUInt(s.substr(d2 + 1), 4, c))
        return false;
    out.major = (unsigned)a;
    out.minor = (unsigned)b;
    out.patch = (unsigned)c;
    return true;
}

int CompareVersion(const Version& a, const Version& b)
{
    if (a.major != b.major) return a.major < b.major ? -1 : 1;
    if (a.minor != b.minor) return a.minor < b.minor ? -1 : 1;
    if (a.patch != b.patch) return a.patch < b.patch ? -1 : 1;
    return 0;
}

std::string VersionToString(const Version& v)
{
    return std::to_string(v.major) + "." + std::to_string(v.minor) + "." +
           std::to_string(v.patch);
}

std::wstring VersionToWide(const Version& v)
{
    return std::to_wstring(v.major) + L"." + std::to_wstring(v.minor) + L"." +
           std::to_wstring(v.patch);
}

Version CurrentVersion()
{
    Version v;
    ParseVersion(NETVIGIL_VERSION, v);   // a malformed constant leaves 0.0.0: updates still work
    return v;
}

// ---------------------------------------------------------------- primitives

std::string ToHex(const unsigned char* p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(digits[p[i] >> 4]);
        s.push_back(digits[p[i] & 15]);
    }
    return s;
}

bool Sha256(const void* data, size_t n, unsigned char out[32])
{
    if (n > 0xFFFFFFFFull) return false;     // BCryptHash takes a ULONG length
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return false;
    NTSTATUS st = BCryptHash(alg, nullptr, 0, (PUCHAR)data, (ULONG)n, out, 32);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0;
}

bool VerifyP256(const unsigned char* pub65, const void* data, size_t n,
                const unsigned char* sig64)
{
    if (!pub65 || !sig64 || pub65[0] != 0x04) return false;   // uncompressed point only

    unsigned char digest[32];
    if (!Sha256(data, n, digest)) return false;

    // BCRYPT_ECCKEY_BLOB header followed by X and Y (32 bytes each).
    std::vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    BCRYPT_ECCKEY_BLOB hdr{ BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32 };
    std::memcpy(blob.data(), &hdr, sizeof hdr);
    std::memcpy(blob.data() + sizeof hdr, pub65 + 1, 64);

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0)
        return false;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool ok = false;
    // ImportKeyPair rejects a point that is not on the curve.
    if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, blob.data(),
                            (ULONG)blob.size(), 0) >= 0) {
        ok = BCryptVerifySignature(key, nullptr, digest, sizeof digest, (PUCHAR)sig64, 64, 0) >= 0;
        BCryptDestroyKey(key);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// ---------------------------------------------------------------- manifest

static bool IsLowerHex(const std::string& s, size_t len)
{
    if (s.size() != len) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

static bool FromHex(const std::string& s, unsigned char* out)
{
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out[i / 2] = (unsigned char)((nib(s[i]) << 4) | nib(s[i + 1]));
    }
    return true;
}

static bool TakeLine(const std::string& t, size_t& pos, std::string& line)
{
    size_t e = t.find('\n', pos);
    if (e == std::string::npos) return false;
    line = t.substr(pos, e - pos);
    pos = e + 1;
    return true;
}

static bool StartsWith(const std::string& s, const char* prefix, std::string& rest)
{
    size_t n = std::strlen(prefix);
    if (s.compare(0, n, prefix) != 0) return false;
    rest = s.substr(n);
    return true;
}

ManifestResult ParseSignedManifest(const std::string& text, const unsigned char* pub65,
                                   UpdateManifest& out)
{
    if (text.empty() || text.size() > kMaxManifestBytes) return ManifestResult::Malformed;
    // Fixed alphabet: printable ASCII plus LF. No CR, NUL, tabs or high bytes.
    for (unsigned char c : text)
        if (c != '\n' && (c < 0x20 || c > 0x7e)) return ManifestResult::Malformed;

    size_t pos = 0;
    std::string l1, l2, l3, l4, l5;
    if (!TakeLine(text, pos, l1) || !TakeLine(text, pos, l2) || !TakeLine(text, pos, l3) ||
        !TakeLine(text, pos, l4) || !TakeLine(text, pos, l5) || pos != text.size())
        return ManifestResult::Malformed;               // exactly five LF-terminated lines

    std::string ver, size, sha, sigHex;
    if (l1 != "netvigil-update-v1" || !StartsWith(l2, "version=", ver) ||
        !StartsWith(l3, "size=", size) || !StartsWith(l4, "sha256=", sha) ||
        !StartsWith(l5, "sig=", sigHex))
        return ManifestResult::Malformed;
    if (!IsLowerHex(sha, 64) || !IsLowerHex(sigHex, 128)) return ManifestResult::Malformed;

    // Authenticate BEFORE looking at what the fields say.
    unsigned char sig[64];
    FromHex(sigHex, sig);
    size_t payloadLen = l1.size() + l2.size() + l3.size() + l4.size() + 4;   // four lines + LFs
    if (!VerifyP256(pub65, text.data(), payloadLen, sig)) return ManifestResult::BadSignature;

    Version v;
    unsigned long long bytes = 0;
    if (!ParseVersion(ver, v) || !ParseUInt(size, 8, bytes) ||
        bytes < kMinUpdateExeBytes || bytes > kMaxUpdateExeBytes)
        return ManifestResult::Malformed;

    out.version = v;
    out.size = bytes;
    out.sha256 = sha;
    return ManifestResult::Ok;
}

bool ExeMatchesManifest(const void* data, size_t n, const UpdateManifest& m)
{
    if (n != m.size || n < 2) return false;
    const unsigned char* p = (const unsigned char*)data;
    if (p[0] != 'M' || p[1] != 'Z') return false;                   // a PE file
    unsigned char digest[32];
    if (!Sha256(data, n, digest)) return false;
    return ToHex(digest, 32) == m.sha256;
}

} // namespace nv
