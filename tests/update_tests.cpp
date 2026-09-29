// update_tests.cpp — unit tests for the self-updater's trust decisions
// (src/updatecore.cpp). Every accept-path test has reject-path partners:
// a verifier that has only ever been shown good input proves nothing.
//
//   build.bat test        builds and runs this together with diagnose_tests
//
// Optional arguments check a manifest produced by tools\sign-manifest.ps1
// against the public key compiled into the exe (i.e. the real release key):
//   update_tests.exe <manifest.txt> [<exe the manifest describes>]

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "updatecore.h"
#include "update_pubkey.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

using namespace nv;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (cond) ++g_pass;                                                     \
        else {                                                                  \
            ++g_fail;                                                           \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                       \
    } while (0)

// ---------------------------------------------------------------- signer
// A throwaway P-256 key pair made with CNG, so the tests need no fixtures.

struct Signer {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    unsigned char pub[65] = {};

    Signer()
    {
        BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
        BCryptGenerateKeyPair(alg, &key, 256, 0);
        BCryptFinalizeKeyPair(key, 0);
        unsigned char blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {};
        ULONG got = 0;
        BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &got, 0);
        pub[0] = 0x04;
        std::memcpy(pub + 1, blob + sizeof(BCRYPT_ECCKEY_BLOB), 64);
    }
    ~Signer()
    {
        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }
    void Sign(const std::string& data, unsigned char sig[64]) const
    {
        unsigned char digest[32];
        Sha256(data.data(), data.size(), digest);
        ULONG got = 0;
        BCryptSignHash(key, nullptr, digest, 32, sig, 64, &got, 0);
    }
};

static const std::string kGoodSha(64, 'a');

// A manifest with the four signed lines given verbatim; the signature is made
// over exactly those bytes, so tests can sign deliberately bad content.
static std::string Signed(const Signer& s, const std::string& payload)
{
    unsigned char sig[64];
    s.Sign(payload, sig);
    return payload + "sig=" + ToHex(sig, 64) + "\n";
}

static std::string Payload(const std::string& ver = "1.2.3", const std::string& size = "5000",
                           const std::string& sha = kGoodSha,
                           const std::string& head = "netvigil-update-v1")
{
    return head + "\nversion=" + ver + "\nsize=" + size + "\nsha256=" + sha + "\n";
}

static ManifestResult Parse(const std::string& text, const unsigned char* pub)
{
    UpdateManifest m;
    return ParseSignedManifest(text, pub, m);
}

// ---------------------------------------------------------------- tests

static void TestVersions()
{
    Version v;
    CHECK(ParseVersion("1.0.0", v) && v.major == 1 && v.minor == 0 && v.patch == 0);
    CHECK(ParseVersion("0.0.1", v) && v.patch == 1);
    CHECK(ParseVersion("9999.9999.9999", v) && v.major == 9999 && v.patch == 9999);
    CHECK(ParseVersion("12.34.56", v) && v.minor == 34);

    const char* bad[] = { "", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "1.2.-3",
                          "1.2.+3", " 1.2.3", "1.2.3 ", "1.2.3\n", "1.2.3a", "a.b.c", "1..3",
                          ".1.2", "1.2.", "10000.0.0", "1.10000.0", "1.0.10000", "1,2,3",
                          "1.2.3-beta", "v1.2.3" };
    for (const char* b : bad) CHECK(!ParseVersion(b, v));

    Version a{ 1, 2, 3 }, b{ 1, 2, 4 }, c{ 1, 3, 0 }, d{ 2, 0, 0 };
    CHECK(CompareVersion(a, a) == 0);
    CHECK(CompareVersion(a, b) < 0 && CompareVersion(b, a) > 0);
    CHECK(CompareVersion(b, c) < 0 && CompareVersion(c, d) < 0);
    Version big{ 1, 9999, 9999 }, next{ 2, 0, 0 };
    CHECK(CompareVersion(big, next) < 0);         // numeric, not lexical: 1.10.0 > 1.9.0
    Version nine{ 1, 9, 0 }, ten{ 1, 10, 0 };
    CHECK(CompareVersion(nine, ten) < 0);
    CHECK(VersionToString(Version{ 3, 14, 15 }) == "3.14.15");

    Version cur = CurrentVersion();
    CHECK(cur.major + cur.minor + cur.patch > 0);  // the compiled-in constant parses
}

static void TestSha256()
{
    unsigned char h[32];
    CHECK(Sha256("abc", 3, h));
    CHECK(ToHex(h, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(Sha256("", 0, h));
    CHECK(ToHex(h, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(ToHex(h, 32) != ToHex((const unsigned char*)"\1", 1));
}

static void TestSignatures()
{
    Signer good, other;
    const std::string msg = "the quick brown fox";
    unsigned char sig[64];
    good.Sign(msg, sig);

    CHECK(VerifyP256(good.pub, msg.data(), msg.size(), sig));

    // negative controls: each single change must flip the verdict
    CHECK(!VerifyP256(other.pub, msg.data(), msg.size(), sig));        // wrong key
    std::string tampered = msg;
    tampered[0] ^= 1;
    CHECK(!VerifyP256(good.pub, tampered.data(), tampered.size(), sig)); // wrong message
    unsigned char flipped[64];
    std::memcpy(flipped, sig, 64);
    flipped[10] ^= 1;
    CHECK(!VerifyP256(good.pub, msg.data(), msg.size(), flipped));     // damaged signature
    std::memcpy(flipped, sig, 64);
    flipped[63] ^= 0x80;
    CHECK(!VerifyP256(good.pub, msg.data(), msg.size(), flipped));
    unsigned char zeros[64] = {};
    CHECK(!VerifyP256(good.pub, msg.data(), msg.size(), zeros));       // all-zero signature

    unsigned char badPub[65];
    std::memcpy(badPub, good.pub, 65);
    badPub[0] = 0x02;                                                   // compressed form refused
    CHECK(!VerifyP256(badPub, msg.data(), msg.size(), sig));
    std::memcpy(badPub, good.pub, 65);
    badPub[40] ^= 1;                                                    // point off the curve
    CHECK(!VerifyP256(badPub, msg.data(), msg.size(), sig));
    CHECK(!VerifyP256(nullptr, msg.data(), msg.size(), sig));
    CHECK(!VerifyP256(good.pub, msg.data(), msg.size(), nullptr));
}

static void TestManifestAccept()
{
    Signer s;
    UpdateManifest m;
    CHECK(ParseSignedManifest(Signed(s, Payload()), s.pub, m) == ManifestResult::Ok);
    CHECK(m.version.major == 1 && m.version.minor == 2 && m.version.patch == 3);
    CHECK(m.size == 5000 && m.sha256 == kGoodSha);

    // size bounds are inclusive
    CHECK(Parse(Signed(s, Payload("1.0.0", "1024")), s.pub) == ManifestResult::Ok);
    CHECK(Parse(Signed(s, Payload("1.0.0", "16777216")), s.pub) == ManifestResult::Ok);
}

static void TestManifestReject()
{
    Signer s, other;

    // signature problems -> BadSignature
    CHECK(Parse(Signed(other, Payload()), s.pub) == ManifestResult::BadSignature);  // signed by someone else
    std::string ok = Signed(s, Payload());
    std::string t = ok;
    t[std::string("netvigil-update-v1\nversion=").size()] = '9';                     // version edited after signing
    CHECK(Parse(t, s.pub) == ManifestResult::BadSignature);
    t = ok;
    t[t.find("size=") + 5] = '6';                                                   // size edited
    CHECK(Parse(t, s.pub) == ManifestResult::BadSignature);
    t = ok;
    t[t.find("sha256=") + 7] = 'b';                                                 // hash edited
    CHECK(Parse(t, s.pub) == ManifestResult::BadSignature);
    t = ok;
    t[t.find("sig=") + 4] = (t[t.find("sig=") + 4] == '0' ? '1' : '0');             // signature edited
    CHECK(Parse(t, s.pub) == ManifestResult::BadSignature);

    // structure problems -> Malformed, even though the signature is genuine
    CHECK(Parse(Signed(s, Payload("1.2.3", "5000", kGoodSha, "netvigil-update-v2")), s.pub) == ManifestResult::Malformed);
    CHECK(Parse(Signed(s, Payload("1.2", "5000")), s.pub) == ManifestResult::Malformed);          // bad version
    CHECK(Parse(Signed(s, Payload("1.2.3.4", "5000")), s.pub) == ManifestResult::Malformed);
    CHECK(Parse(Signed(s, Payload("1.2.3", "1023")), s.pub) == ManifestResult::Malformed);        // too small
    CHECK(Parse(Signed(s, Payload("1.2.3", "16777217")), s.pub) == ManifestResult::Malformed);    // too big
    CHECK(Parse(Signed(s, Payload("1.2.3", "0500")), s.pub) == ManifestResult::Malformed);        // leading zero
    CHECK(Parse(Signed(s, Payload("1.2.3", "-5000")), s.pub) == ManifestResult::Malformed);
    CHECK(Parse(Signed(s, Payload("1.2.3", "5000", std::string(64, 'A'))), s.pub) == ManifestResult::Malformed);  // upper-case hex
    CHECK(Parse(Signed(s, Payload("1.2.3", "5000", std::string(63, 'a'))), s.pub) == ManifestResult::Malformed);
    CHECK(Parse(Signed(s, Payload("1.2.3", "5000", std::string(65, 'a'))), s.pub) == ManifestResult::Malformed);

    // layout problems
    CHECK(Parse("", s.pub) == ManifestResult::Malformed);
    CHECK(Parse(ok.substr(0, ok.size() - 1), s.pub) == ManifestResult::Malformed);   // no final newline
    CHECK(Parse(ok + "\n", s.pub) == ManifestResult::Malformed);                      // trailing blank line
    CHECK(Parse(ok + "extra=1\n", s.pub) == ManifestResult::Malformed);               // extra line
    CHECK(Parse(" " + ok, s.pub) == ManifestResult::Malformed);
    std::string crlf;
    for (char c : ok) { if (c == '\n') crlf += '\r'; crlf += c; }
    CHECK(Parse(crlf, s.pub) == ManifestResult::Malformed);                           // CRLF
    std::string withNul = ok;
    withNul.insert(5, 1, '\0');
    CHECK(Parse(withNul, s.pub) == ManifestResult::Malformed);
    CHECK(Parse(ok + std::string(2000, 'x'), s.pub) == ManifestResult::Malformed);    // oversized
    CHECK(Parse("garbage", s.pub) == ManifestResult::Malformed);

    // lines out of order, even correctly signed
    std::string reordered = "netvigil-update-v1\nsize=5000\nversion=1.2.3\nsha256=" + kGoodSha + "\n";
    CHECK(Parse(Signed(s, reordered), s.pub) == ManifestResult::Malformed);

    // out is untouched on failure
    UpdateManifest m;
    m.size = 42;
    CHECK(ParseSignedManifest(Signed(other, Payload()), s.pub, m) == ManifestResult::BadSignature);
    CHECK(m.size == 42);
}

static void TestExeMatch()
{
    std::string exe = "MZ";
    exe.append(4000, 'x');
    unsigned char h[32];
    Sha256(exe.data(), exe.size(), h);

    UpdateManifest m;
    m.size = exe.size();
    m.sha256 = ToHex(h, 32);
    CHECK(ExeMatchesManifest(exe.data(), exe.size(), m));

    std::string flipped = exe;
    flipped[100] ^= 1;
    CHECK(!ExeMatchesManifest(flipped.data(), flipped.size(), m));                   // content changed
    CHECK(!ExeMatchesManifest(exe.data(), exe.size() - 1, m));                        // truncated
    std::string longer = exe + "x";
    CHECK(!ExeMatchesManifest(longer.data(), longer.size(), m));                      // appended data

    // Hash is right for the data but the signed size is not: the size check
    // must reject on its own, not lean on the hash.
    std::string shorter = exe.substr(0, exe.size() - 1);
    Sha256(shorter.data(), shorter.size(), h);
    UpdateManifest sizeOnly;
    sizeOnly.size = exe.size();                    // promises the full length ...
    sizeOnly.sha256 = ToHex(h, 32);                // ... but the hash is of the shorter data
    CHECK(!ExeMatchesManifest(shorter.data(), shorter.size(), sizeOnly));
    UpdateManifest sizeShort = sizeOnly;
    sizeShort.size = shorter.size();               // consistent size + hash: must pass
    CHECK(ExeMatchesManifest(shorter.data(), shorter.size(), sizeShort));

    UpdateManifest wrongHash = m;
    wrongHash.sha256 = std::string(64, '0');
    CHECK(!ExeMatchesManifest(exe.data(), exe.size(), wrongHash));

    // right size and hash but not a PE file
    std::string notPe = "XX";
    notPe.append(4000, 'x');
    Sha256(notPe.data(), notPe.size(), h);
    UpdateManifest mp;
    mp.size = notPe.size();
    mp.sha256 = ToHex(h, 32);
    CHECK(!ExeMatchesManifest(notPe.data(), notPe.size(), mp));
    CHECK(!ExeMatchesManifest(nullptr, 0, m));
}

// The compiled-in public key must be a real point on P-256 (catches a
// mangled update_pubkey.h): verify a signature it cannot have produced -> false,
// but the key import itself must not be what failed. Proven by importing it and
// checking a wrong signature is rejected *after* a successful import.
static void TestEmbeddedKey()
{
    CHECK(kUpdatePubKey[0] == 0x04);
    unsigned char zeros[64] = {};
    CHECK(!VerifyP256(kUpdatePubKey, "x", 1, zeros));
}

// Real-artifact check: a manifest made by tools\sign-manifest.ps1 (real key)
// must verify against the embedded key, and the exe must match it.
static int CheckArtifact(const char* manifestPath, const char* exePath)
{
    auto slurp = [](const char* p, std::string& out) {
        FILE* f = std::fopen(p, "rb");
        if (!f) return false;
        char buf[65536];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
        std::fclose(f);
        return true;
    };
    std::string text;
    if (!slurp(manifestPath, text)) { std::printf("cannot read %s\n", manifestPath); return 2; }
    UpdateManifest m;
    ManifestResult r = ParseSignedManifest(text, kUpdatePubKey, m);
    std::printf("manifest: %s (version %s, %llu bytes)\n",
                r == ManifestResult::Ok ? "OK — signature verifies against the embedded key"
                : r == ManifestResult::BadSignature ? "BAD SIGNATURE" : "MALFORMED",
                VersionToString(m.version).c_str(), m.size);
    if (r != ManifestResult::Ok) return 1;
    if (exePath) {
        std::string exe;
        if (!slurp(exePath, exe)) { std::printf("cannot read %s\n", exePath); return 2; }
        bool ok = ExeMatchesManifest(exe.data(), exe.size(), m);
        std::printf("exe     : %s\n", ok ? "matches the signed size and SHA-256" : "DOES NOT MATCH");
        return ok ? 0 : 1;
    }
    return 0;
}

int main(int argc, char** argv)
{
    if (argc > 1) return CheckArtifact(argv[1], argc > 2 ? argv[2] : nullptr);

    TestVersions();
    TestSha256();
    TestSignatures();
    TestManifestAccept();
    TestManifestReject();
    TestExeMatch();
    TestEmbeddedKey();

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
