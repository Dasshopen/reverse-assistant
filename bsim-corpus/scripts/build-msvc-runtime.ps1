[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$corpusRoot = Split-Path $scriptDir -Parent
$buildDir = Join-Path $corpusRoot "build\msvc-runtime-x64-release-syms"

. (Join-Path $scriptDir "lib\VsEnv.ps1")
Import-VisualStudioX64Environment

if (Test-Path -LiteralPath $buildDir) {
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$source = Join-Path $buildDir "msvc-runtime-reference.cpp"
$exe = Join-Path $buildDir "msvc-runtime-reference.exe"
$pdb = Join-Path $buildDir "msvc-runtime-reference.pdb"
$compilerPdb = Join-Path $buildDir "msvc-runtime-reference-compile.pdb"
$toolchain = Join-Path $buildDir "toolchain.txt"

# This binary is generated locally and is never shipped. /MT deliberately
# pulls the installed MSVC/UCRT implementation into one symbol-rich reference
# executable so BSim can learn the runtime version actually present on the
# user's machine. The ra_reference_* wrappers are plainly prefixed so their
# provenance can never be confused with Microsoft runtime symbols.
@'
#include <algorithm>
#include <charconv>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <locale>
#include <memory>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

static volatile std::size_t ra_sink = 0;

__declspec(noinline) void ra_reference_stdio(const char* path) {
    FILE* file = nullptr;
    fopen_s(&file, path, "rb");
    if (file != nullptr) {
        char buffer[128]{};
        ra_sink += fread(buffer, 1, sizeof(buffer), file);
        fclose(file);
    }
}

__declspec(noinline) void ra_reference_strings(const char* value) {
    std::string text(value ? value : "");
    std::wstring wide(text.begin(), text.end());
    std::regex expression("[A-Za-z_][A-Za-z0-9_]*");
    ra_sink += std::regex_search(text, expression) ? 1u : 0u;
    ra_sink += wide.size();
}

__declspec(noinline) void ra_reference_containers(int seed) {
    std::vector<int> values{seed, 7, 3, 11, 2, 5};
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    ra_sink += static_cast<std::size_t>(values.at(values.size() / 2));
}

__declspec(noinline) void ra_reference_filesystem(const char* path) {
    std::error_code error;
    const auto status = std::filesystem::status(path ? path : ".", error);
    ra_sink += std::filesystem::exists(status) ? 1u : 0u;
    ra_sink += error.value();
}

__declspec(noinline) void ra_reference_conversion(const char* value) {
    int parsed = 0;
    const char* begin = value ? value : "0";
    const char* end = begin + std::strlen(begin);
    const auto result = std::from_chars(begin, end, parsed);
    char output[32]{};
    const auto rendered = std::to_chars(output, output + sizeof(output), parsed);
    ra_sink += static_cast<std::size_t>(result.ec == std::errc{});
    ra_sink += static_cast<std::size_t>(rendered.ptr - output);
}

__declspec(noinline) void ra_reference_synchronization() {
    std::mutex mutex;
    std::condition_variable condition;
    bool ready = false;
    std::thread worker([&] {
        std::lock_guard<std::mutex> lock(mutex);
        ready = true;
        condition.notify_one();
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return ready; });
    }
    worker.join();
    ra_sink += ready ? 1u : 0u;
}

__declspec(noinline) void ra_reference_exceptions(int value) {
    try {
        if (value < 0) throw std::invalid_argument("negative value");
        if (value == 0) throw std::runtime_error("zero value");
        auto object = std::make_unique<std::string>("runtime");
        ra_sink += object->size();
    } catch (const std::exception& error) {
        ra_sink += std::strlen(error.what());
    }
}

int main(int argc, char** argv) {
    const char* input = argc > 1 ? argv[1] : "42";
    ra_reference_stdio(input);
    ra_reference_strings(input);
    ra_reference_containers(argc);
    ra_reference_filesystem(input);
    ra_reference_conversion(input);
    ra_reference_synchronization();
    ra_reference_exceptions(argc - 2);
    return static_cast<int>(ra_sink & 0xffu);
}
'@ | Set-Content -LiteralPath $source -Encoding UTF8

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& cl.exe /nologo /std:c++17 /O2 /Zi /MT /EHsc /GL- "/Fo$buildDir\" "/Fd$compilerPdb" "/Fe$exe" $source /link /DEBUG:FULL /INCREMENTAL:NO "/PDB:$pdb"
$exitCode = $LASTEXITCODE
& cl.exe /Bv 2>&1 | Set-Content -LiteralPath $toolchain -Encoding UTF8
$ErrorActionPreference = $previousErrorActionPreference
if ($exitCode -ne 0) {
    throw "cl.exe failed to build the local MSVC runtime reference"
}

if (-not (Test-Path -LiteralPath $exe -PathType Leaf) -or -not (Test-Path -LiteralPath $pdb -PathType Leaf)) {
    throw "MSVC runtime reference build completed without producing the expected EXE/PDB"
}

Write-Host "Built local MSVC runtime reference: $exe"
Write-Host "Symbols: $pdb"
Write-Host "Toolchain provenance: $toolchain"
