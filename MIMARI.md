# Mimari

Bu belge her parçanın ne yaptığını ve neden var olduğunu anlatıyor.
Komut satırı kullanımını görmek için `docs/KULLANIM.md`'a, anti-cheat
katmanlarının tam analizi için `docs/ANTI_CHEAT.md` ve
`docs/THEMIDA_BYPASS.md`'a bakın.

## Problem özeti

`Goley_.exe` üç şeyin üst üste binmesi:

1. **Themida 2.x** (Oreans, 2014 yılı build'i) ile pack'lenmiş.
2. **INCA nProtect GameGuard** ile linkli (CC2 jenerasyonu).
3. 32-bit Windows GUI uygulaması; orijinal Joygame sunucularına
   ProudNet (Nettention) protokolü ile bağlanmaya çalışıyor.

Sunucular 2018'de kapandı. Client'ı kendi kendine açmak istiyorsak
Themida'yı ve nProtect'i geçmemiz, sonra da kendi sunucumuza
yönlendirmek için ProudNet emulasyonu yazmamız lazım.

Bu repo Themida + nProtect bypass kısmına ve server emulator'a
odaklanıyor. İkisi de aynı çatı altında.

## İki yol var

Anti-cheat'i iki ayrı şekilde geçebilirsiniz. Hangi yol size uygunsa
seçin:

```
+----------------------------------+----------------------------------+
| YOL A: canlı bypass              | YOL B: statik binary patch       |
| (orijinal Themida'lı binary)     | (önceden unpack edilmiş dump)    |
+----------------------------------+----------------------------------+
| Hedef:  Goley_.exe (Themida)     | Hedef:  unpacked_Goley_.exe      |
| Komut:  revival_tool launch        | Komut:  revival_tool patch         |
|                                  |         revival_tool launch-unpacked|
| DLL:    revival_patcher.dll        | DLL:    Yok                      |
| IFEO:   Evet (child re-exec      | IFEO:   Hayır                    |
|         için gerekli)            |                                  |
| Artı:   Orijinal layout korunur, | Artı:   Themida yarışı yok,      |
|         runtime'da her şeye      |         standalone exe,          |
|         müdahale edilebilir      |         DLL/admin gerektirmez    |
| Eksi:   Themida + nProtect       | Eksi:   Önce unpack lazım,       |
|         self-protect'e karşı     |         sadece patch'lediğimiz    |
|         sert yarış koşulu        |         şeyler düzelir           |
+----------------------------------+----------------------------------+
```

`docs/DURUM.md` her iki yolun nereye kadar geldiğini anlatıyor.

## Bileşenler

### revival_tool.exe (`src/tool/`)

32-bit konsol binary'si. Tek noktadan tüm iş akışını sürür. Komutları
README'de tablo halinde.

Neden 32-bit: `dump-threads` ve `unpack` Goley_'nin 32-bit CONTEXT
yapılarını okumak zorunda. 64-bit tool olsa `Wow64GetThreadContext`
ile ekstra plumbing gerekirdi, hiçbir kazancı olmadan. Yani: hepsi
x86.

Hardcoded yol yok. Tool kendi yolunu (`GetModuleFileNameA`) ile
öğreniyor, ondan iki seviye yukarı çıkınca repo kökü çıkar. Goley
kurulum yolu için `GOLEY_INSTALL_DIR` environment variable'ı destekli
(varsayılan `C:\Joygame\Goley\BinaryTr`).

### revival_patcher.dll (`src/patcher/`)

Goley_.exe'ye inject edilen DLL. `DllMain DLL_PROCESS_ATTACH` içinde
inline armor kurar, ardından PatchThread'i async olarak başlatır.

Inline armor: `kernel32!TerminateProcess`, `ExitProcess`,
`ntdll!NtTerminateProcess`, `RtlExitUserProcess`, `NtTerminateThread`
API'lerini `mov eax,1 ; ret N` stub'larına çevirir. Sonra
`AddVectoredExceptionHandler` ile VEH kurar. Hepsi DllMain dönmeden,
yaklaşık 8 milisaniye içinde.

Sebep: wrapper.exe `LoadLibrary` çağırdıktan hemen sonra ResumeThread
çağırıyor. ResumeThread sonrası Themida 7 ms içinde unpack'e başlayıp
self-suicide kararı verebilir. Eğer PatchThread async ise (eski
versiyondaki gibi), MinHook init'i hala çalışırken Themida bizi
öldürür. Inline armor bu yarışı mimari olarak kazanır.

PatchThread: VEH handler valid, MinHook init, HW BP refresh loop.
DllMain döndükten sonra background'da çalışır, asla loader lock
içinde değildir.

DLL kendi yolunu DllMain'de `GetModuleFileNameA` ile öğrenir,
log dosyasını repo köküne yazar (`<repo>\patcher.log`).

### revival_wrapper.exe (`src/wrapper/`)

`Goley_.exe` için IFEO `Debugger` kaydı olarak set edilir. Windows
her `CreateProcess(Goley_)` çağrısını şu şekilde çevirir:

```
revival_wrapper.exe  <Goley_.exe yolu>  <orijinal arg'lar>
```

Wrapper:

1. `CreateProcessW(Goley_.exe, CREATE_SUSPENDED, ...)` çağırır.
2. `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)`
   ile patcher.dll'i inject eder.
3. `ResumeThread` ile child'ı başlatır.
4. Child'ın exit etmesini bekler ve onun exit code'unu döner.

Recursion guard'ı (`GLY_NO_WRAPPER` environment variable):
wrapper'ın kendi `CreateProcess(Goley_)` çağrısı yine IFEO'ya
takılıp wrapper'a yönlenirse sonsuz döngü olur. Env var ile child
process buna girdiğini anlar, `DEBUG_PROCESS | CREATE_SUSPENDED`
kullanıp hemen `DebugActiveProcessStop` ile detach yapar; OS bizi
"eski-debugger" sayar ve IFEO'yu uygulamaz.

Wrapper kendi yolundan DLL ve log path'lerini hesaplar. Yine
hardcoded yol yok.

### apply_patches.py (`src/tool/`)

Standalone Python script'i. IDA Pro gerektirmez.

* `patches.json`'u okur.
* Hedef binary'i açar, PE section table'dan RVA -> file offset
  mapping çıkarır.
* Her patch entry'si için patched bytes'i doğru offset'e yazar.
* Output binary'i kaydeder.

`revival_tool patch <in> <out>` arka planda bunu çağırıyor.

### decrypt.py (`src/extract/`)

Anipark'ın custom cipher'ını Unicorn x86 emulator'ünde çalıştırıp
VLH/VLD oyun dosyalarını çözer.

* Master anahtar: `MD5("VolanteEncryptKey_84106141")` (sabit).
* Master ile VLH'i çözersin, içinden 16 byte ASCII anahtar çıkar.
* O ASCII anahtarın MD5'i ile VLD'yi çözersin.
* VLD içinde zlib stream'leri var, her biri bir dosya.

Cipher'ı Python'a tam port etmek yerine Goley'in kendi decrypt
fonksiyonunu (memory dump'tan çıkarılmış `goley_real_code.bin`)
Unicorn'da çalıştırıyoruz. Böylece Anipark cipher'ında bir edge case
varsa biz de aynısına takılıyoruz. Detay için `src/extract/README.md`.

## Veri akışı (Yol A, Themida'lı)

```
kullanıcı  ──┐
             ▼
revival_tool launch
             │
             │ 1) IFEO Debugger kaydını set eder
             │ 2) CreateProcessA(Goley_, CREATE_SUSPENDED)
             ▼
OS IFEO'yu görür, revival_wrapper.exe'ye yönlendirir
             │
             ▼
revival_wrapper.exe
             │
             │ 1) CreateProcessW(Goley_.exe, CREATE_SUSPENDED)
             │ 2) LoadLibrary ile patcher.dll'i child'a inject
             │    DllMain çalışır: inline armor + VEH + PatchThread
             │ 3) ResumeThread(Goley_'nin ana thread'i)
             ▼
Goley_.exe ana thread çalışmaya başlıyor
             │
             │ Themida unpack başlıyor.
             │ Validation BP'sinde VEH EIP'yi yeniden yazıyor.
             │ INT3'lerde VEH EIP'yi 1 ileri taşıyor.
             │ MinHook hook'ları aktifleşti, child re-exec olursa
             │ o child'a da DLL inject ediyoruz.
             ▼
"ChaguChagu V31927" splash + "초기화중" yazısı
             │
             │ Burada takılıyor. nProtect GameMon ready event'ini
             │ bekliyor, biz GameMon'u çalıştırmadık.
             ▼
(docs/DURUM.md son durumu anlatıyor)
```

## Veri akışı (Yol B, statik patch)

```
kullanıcı ─── revival_tool patch in.exe out.exe
                         │
                         │ apply_patches.py patches.json'u okur,
                         │ PE section table ile RVA -> file offset,
                         │ byte'ları uygular.
                         ▼
revival_tool launch-unpacked
                         │
                         │ unpacked + patched binary'i admin olarak
                         │ başlatır. Themida yok, sadece nProtect
                         │ kalıntıları ve onlar zaten patch'lendi.
                         ▼
(splash görünür, init benzeri bir noktada bekliyor)
```

## Server tarafı (`server/`)

Goley'in artık var olmayan sunucularının yerini tutan, Go ile
sıfırdan yazılmış emulator. Anipark'ın ProudNet (Nettention)
protokolünün re-implementation'ı. Resmi ProudNet kaynak kodu
kullanmıyoruz; sadece gözlemlediğimiz davranışı modelliyoruz.

Bileşenler:

* `cmd/entry-server` (TCP 2270): login + karakter slot listesi
* `cmd/lobby-server` (TCP 2271): oda listesi + lobby chat
* `cmd/battle-server` (TCP 2272 + UDP): maç kurma + NAT relay
* `cmd/daum-auth` (HTTP): Daum login emulasyonu
* `cmd/patch-server` (HTTP 80): client update kontrolü
* `cmd/launcher-web` (HTTP 8080): MSHTML launcher sayfası
* `internal/proudnet/`: ortak network stack (framing, RMI, UDP relay)

Detay için `server/README.md` ve `server/docs/protocol-notes.md`.

### Client/Server akışı

```
Client (Goley_.exe + patcher.dll)
       │
       │ Phase 1: Launcher
       │   1. MSHTML WebView -> launcher-web (HTTP 8080)
       │   2. WinINet GET    -> patch-server (HTTP 80)
       │   3. Hash check + binary update kararı
       │
       │ Phase 2: Login
       │   4. TCP connect    -> entry-server (2270)
       │   5. RequestLogin -> NotifyLoginOk + token
       │
       │ Phase 3: Lobby
       │   6. TCP connect    -> lobby-server (2271)
       │   7. Oda listesi, chat
       │   8. GotoGameRoom + roomGuid
       │
       │ Phase 4: Maç
       │   9. TCP + UDP      -> battle-server (2272)
       │  10. Client'lar arası P2P sync (server sadece relay)
       ▼
```

Önemli detay: Goley'in match logic'i **client-side**. Yani gerçek
oyun mantığı client'ların kendi arasında P2P sync ile akıyor. Server
sadece authentication, matchmaking ve P2P olmazsa relay yapıyor.

## Bu repo'da bulunmayan şeyler

* **Themida unpacking otomasyonu.** `revival_tool unpack <pid>` runtime
  memory'sini PE olarak yazmak için bir deney scaffold'u, ama henüz
  Scylla seviyesinde olgun değil (IAT fix-up yok). Production için
  manuel ImpRec/Scylla önerilir.
* **Eski recon script'leri.** Yaklaşık 150 ayrı tek seferlik Python
  ve PowerShell. Geliştirme kalıntısı. Bu repo'da temizledik.
* **Resmi ProudNet kaynak kodu.** Nettention'ın malı. Burada sadece
  gözlemlediğimiz protokol davranışının Go re-implementation'ı var.
