# Build

Bu repodaki her şey 32-bit Windows hedefli C/C++ (client tarafı) veya
Go (server tarafı). Derleyici **Visual Studio 2022 Build Tools**
(veya tam VS 2022 kurulumu) ve **Go 1.22+**.

## Gereksinimler

Client tarafı için:

* Windows 10 veya 11.
* Visual Studio 2022 Build Tools. Şu component aktif olmalı:
  **MSVC v143 - VS 2022 C++ x86/x64 build tools**.
  Build script'leri varsayılan yola bakar:
  ```
  C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat
  ```
  Sizinkisi farklı yerde ise her `src/*/build.bat` içindeki `VS_PATH`
  satırını düzenleyin.

VLD/VLH çözücü için:

* Python 3.10+.
* Unicorn paketi:
  ```
  pip install -r src\extract\requirements.txt
  ```

Server tarafı için:

* **Go 1.22+**: `winget install GoLang.Go` ya da https://go.dev/dl/

## Client tarafını build et

Normal `cmd.exe` (build sırasında admin gerekmiyor):

```bat
cd C:\path\to\revival
build_all.bat
```

Üç subbuild sırayla çalışır:

```
=== [1/3] Building revival_tool ===
...
=== [2/3] Building revival_patcher.dll ===
...
=== [3/3] Building revival_wrapper.exe ===
...
=== ALL BUILDS OK ===
```

Artifact'lar her source ağacının yanında oluşur:

```
src/tool/revival_tool.exe
src/patcher/revival_patcher.dll
src/wrapper/revival_wrapper.exe
```

## Tek bir client component'i build et

```bat
cd src\tool    && build.bat
cd src\patcher && build.bat
cd src\wrapper && build.bat
```

Her `build.bat` kendi `vcvars32`'sini set ediyor; Developer Command
Prompt açmanıza gerek yok.

## Neden hepsi 32-bit

`Goley_.exe` 32-bit bir PE. DLL'in onunla aynı bitness olması gerek.
Wrapper IFEO'da onunla aynı bitness olmalı. Tool 32-bit CONTEXT
yapılarını Goley_ thread'lerinden okur; 32-bit tool'da bu basit,
64-bit tool'da `Wow64GetThreadContext` plumbing'i gerekirdi. Yani
hepsi `/MACHINE:X86`.

## Statik CRT (/MT)

Üç bileşen de statik CRT'ye linkleniyor. Yanlarında `vcruntime140.dll`
olmadan taşınabilirler. Boyut maliyeti ~50 KB per binary, kayda
değer değil.

## Path konfigürasyonu

Hardcoded path yok. Her bileşen kendi yolunu runtime'da hesaplıyor:

* `revival_tool.exe`: `GetModuleFileNameA` ile kendi yolunu bulur,
  iki seviye yukarı çıkınca repo kökü çıkar.
* `revival_patcher.dll`: DllMain içinde `GetModuleFileNameA` ile kendi
  yolunu bulur, log dosyasını repo köküne yazar.
* `revival_wrapper.exe`: `wmain` başında kendi yolundan DLL ve log
  path'lerini hesaplar.

Yani repo'yu nereye clone ettiyseniz doğru çalışır.

Goley'in kurulum klasörü için tek yapılandırma:

```bat
set GOLEY_INSTALL_DIR=D:\Oyunlar\Goley\BinaryTr
```

Varsayılan: `C:\Joygame\Goley\BinaryTr`.

## Smoke test

```bat
src\tool\revival_tool.exe ping
:: => ok

src\tool\revival_tool.exe help
:: => komut listesi
```

## VLD/VLH çözücü için ekstra setup

```bat
pip install -r src\extract\requirements.txt

:: Sonra:
src\tool\revival_tool.exe extract
```

Unicorn ilk yüklemede 30-50 MB indirir.

## Server tarafını build

Server tarafı Go ile yazılmış, ayrı bir build adımı var. Detay için
`server/README.md`'a bak.

```bat
cd server
make build
:: veya
go build -o bin/ ./cmd/...
```

`server/bin/` altında her servis için ayrı .exe oluşur. Hepsini aynı
anda başlatmak için:

```bat
.\scripts\start-all.ps1
```

Server için Visual Studio Build Tools'a gerek yok. Sadece Go.
