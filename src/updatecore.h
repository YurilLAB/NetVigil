// updatecore.h — the trust decisions of the self-updater, kept free of
// networking, logging and UI so they can be unit-tested (tests/update_tests.cpp).
//
// An update is accepted only if ALL of these hold:
//   1. the manifest is well-formed (strict, fixed layout, size-capped),
//   2. its ECDSA P-256 / SHA-256 signature verifies against the public key
//      compiled into this exe (update_pubkey.h),
//   3. its version is strictly newer than the running one (no downgrades),
//   4. the downloaded exe has exactly the signed size and SHA-256.
// Anything else is rejected and nothing is written to the install folder.
#pragma once
#include <cstddef>
#include <string>

namespace nv {

struct Version {
    unsigned major = 0, minor = 0, patch = 0;
};

// Strict "a.b.c": three decimal numbers of 1-4 digits, no leading zeros, no
// signs, no whitespace, nothing else.
bool ParseVersion(const std::string& s, Version& out);
int CompareVersion(const Version& a, const Version& b);   // <0, 0, >0
std::string VersionToString(const Version& v);
std::wstring VersionToWide(const Version& v);

const size_t kMaxManifestBytes = 1024;
const unsigned long long kMinUpdateExeBytes = 1024;
const unsigned long long kMaxUpdateExeBytes = 16ull << 20;   // 16 MiB

struct UpdateManifest {
    Version version;
    unsigned long long size = 0;   // bytes of the exe
    std::string sha256;            // 64 lowercase hex digits
};

enum class ManifestResult { Ok, Malformed, BadSignature };

// Parses AND authenticates a signed manifest (layout in tools\sign-manifest.ps1).
// `pub65` is the 65-byte uncompressed P-256 public key. `out` is only filled on Ok.
ManifestResult ParseSignedManifest(const std::string& text, const unsigned char* pub65,
                                   UpdateManifest& out);

// True only if `data` has exactly the size and SHA-256 the manifest promised.
bool ExeMatchesManifest(const void* data, size_t n, const UpdateManifest& m);

// Primitives (Windows CNG). Exposed for the tests.
bool Sha256(const void* data, size_t n, unsigned char out[32]);
std::string ToHex(const unsigned char* p, size_t n);
// ECDSA P-256 over SHA-256(data); sig64 = r||s (IEEE P1363); pub65 = 0x04||X||Y.
bool VerifyP256(const unsigned char* pub65, const void* data, size_t n,
                const unsigned char* sig64);

// The exe's own version, "a.b.c" (src\version.h).
Version CurrentVersion();

} // namespace nv
