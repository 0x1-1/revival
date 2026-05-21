# Kullanım

Tool'u Yönetici olarak açılmış bir komut satırından kullanmanız lazım.
Goley_.exe'nin manifesti `requireAdministrator` olduğu için normal
kullanıcıdan açılmıyor; IFEO registry kaydı HKLM altında; remote
process'e DLL inject için PROCESS_ALL_ACCESS yetkisi gerek.

cmd.exe veya Windows Terminal'i "Yönetici olarak çalıştır" ile açın,
sonra repo'ya gidin:

```bat
cd C:\Users\<sizin_kullanici_adiniz>\Documents\revival
```

(`C:\Users\xxx\Desktop\revival` gibi, nereye clone ettiyseniz.)

## İlk açılış akışı

Bir kerelik yapılan setup ve sonraki açılışların akışı farklı.

### 1) Build

```bat
build_all.bat
```

Üç ayrı program derlenir: tool, patcher DLL, IFEO wrapper. Visual
Studio 2022 Build Tools yüklü olmalı (`BUILD.md` içinde detay).

### 2) Setup'ı tool'a gösterin

Joygame'in eski Goley installer'ını elinizde tutuyorsanız:

```bat
src\tool\revival_tool.exe init "C:\Users\siz\Downloads\GoleySetup.exe"
```

Tool sırayla:
1. Setup'ı başlatır. GUI penceresi açılır, "Kur" deyip bekleyin.
2. Setup'tan çıkınca tool `C:\Joygame\Goley\BinaryTr\Goley_.exe`'nin
   yerli yerinde olduğunu kontrol eder.
3. IFEO Debugger kaydını ayarlar (HKLM, admin gerek).

Goley'i farklı bir klasöre kurduysanız:

```bat
set GOLEY_INSTALL_DIR=D:\Oyunlar\Goley\BinaryTr
src\tool\revival_tool.exe init "C:\Users\siz\Downloads\GoleySetup.exe"
```

Bu environment variable kalıcı değil; her oturumda set etmek lazım
veya kalıcı yapmak istiyorsanız `setx` kullanın.

### 3) Oyunu başlat

```bat
src\tool\revival_tool.exe launch
```

Goley_.exe açılır, DLL inject edilir, Themida bypass devreye girer.

## Log izleme

`patcher.log` dosyasını izleyerek bypass'ın nereye kadar geldiğini
görebilirsiniz. Log dosyası repo kökünde oluşur:

```bat
type patcher.log
```

Canlı takip:

```bat
powershell -Command "Get-Content patcher.log -Wait -Tail 50"
```

Beklenen ilk birkaç satır (launch'tan sonra ~10 ms içinde):

```
[hh:mm:ss.fff P=NNNN] DLL_PROCESS_ATTACH (VEH+HWBP+DialogKiller)
[...]                  Patched [inline] kernel32!TerminateProcess @ 0x...
[...]                  Patched [inline] kernel32!ExitProcess       @ 0x...
[...]                  Patched [inline] ntdll!NtTerminateProcess   @ 0x...
[...]                  [inline] VEH installed
[...]                  PatchThread starting (VEH+HWBP+MinHook refresh-loop mode)
[...]                  MinHook: CreateProcessA/W hooks ACTIVE
```

Sadece "ATTACH" satırını görüp hemen ardından "DETACH" gördüyseniz,
race kaybedildi. Böyle bir şey son release'de olmamalı; oluyorsa
`docs/THEMIDA_BYPASS.md` içindeki "inline armor sırası" bölümüne bakın,
mimari fix'i geri almış olabilirsiniz.

## Oyun verilerini çıkartma

VLH/VLD çiftleri (karakterler, stadyumlar, çeviriler) için:

```bat
:: Şifre çözücü Python script'i için bir kerelik:
pip install unicorn

:: Tüm data klasörünü bir kerede aç:
src\tool\revival_tool.exe extract

:: Veya tek bir çifti:
src\tool\revival_tool.exe extract "C:\Joygame\Goley\Data\Character.VLH" "C:\Joygame\Goley\Data\Character.VLD"
```

Çıktılar `extracted/character/`, `extracted/stadium/`, vs. altında
görülüyor (ne kadar dosya çıktı dahil rapor ediliyor).

## Takılan Goley_'i inceleme

Splash görünüp "초기화중" (Korece: "Yükleniyor") yazısında kalmışsa,
hangi thread'in nerede beklediğini görmek lazım:

```bat
tasklist | findstr /i goley_
:: Goley_.exe için PID'i alın (mesela 12345)

src\tool\revival_tool.exe dump-threads 12345
```

Çıktı her thread'in EIP'sini hangi modülde olduğu ile beraber yazar:

```
tid=23456 EIP=ntdll.dll+0x6E4B0 ESP=0x002FFAE0 | image+0x935AB9 | image+0x8E70E0 | ...
```

`ntdll.dll+...` da bekleyen thread bir senkronizasyon objesinde
duruyor demektir. Stack'in ilk slotu `image+0x...` ise, o adres
Goley_'nin kendi kodunda; IDA ile bakınca hangi handle beklediğini
bulabilirsiniz.

## IFEO yönetimi

Normal şartlarda elle dokunmanıza gerek yok; `init` ve `launch`
otomatik ayarlar. Ama isterseniz:

```bat
src\tool\revival_tool.exe ifeo show     :: mevcut değer
src\tool\revival_tool.exe ifeo set      :: revival_wrapper'i kaydet
src\tool\revival_tool.exe ifeo clear    :: kaldır
```

IFEO neden gerek: nProtect'in "trusted re-launch" davranışı var,
Goley_.exe'yi kendi içinden tekrar spawn ediyor. IFEO Debugger kaydı
revival_wrapper.exe'yi gösterirse, her `CreateProcess(Goley_)` bizim
üzerimizden geçer ve child'a da DLL inject edilir. Kayıt olmadan
child runtime'da bizim DLL'imiz olmadığı için Themida + nProtect tekrar
çalışır ve bütün bypass'larımızı kaybederiz.

## Statik patch yolu (alternatif)

Themida'sız `unpacked_Goley_.exe` elinizde varsa (kendi unpack
ettiyseniz ya da dışarıdan getirdiyseniz), DLL inject etmeden de
nProtect'i atlatabilirsiniz:

```bat
src\tool\revival_tool.exe patch ^
    "C:\Joygame\Goley\BinaryTr\unpacked_Goley_.exe" ^
    "C:\Joygame\Goley\BinaryTr\unpacked_Goley_PATCHED.exe"

src\tool\revival_tool.exe launch-unpacked
```

Bu yöntemde `patches.json` içindeki kayıtlı patch'ler (şu an iki tane)
PE'nin file offset'lerine yazılır. IDA falan gerekmiyor; sadece PE
section table parsing ve byte yazma.

## Temizlik

Bir şey ters gitti, Goley_ Task Manager'dan öldürülmüyor (admin
process), wrapper kalmış falan:

```bat
src\tool\revival_tool.exe cleanup
```

Bu komut idempotent: tüm Goley_/wrapper PID'lerini bulup öldürür,
IFEO kaydını siler. Kaç kez çalıştırsanız da aynı; "her şey temiz"
durumu garanti eder.

## Yeni clone sonrası smoke test

Repo'yu klonladınız, hiçbir şey çalıştırmadınız, doğru çalışıp
çalışmadığını hızlıca anlamak istiyorsunuz:

```bat
build_all.bat                                  :: hata vermesin
src\tool\revival_tool.exe ping                   :: => ok
src\tool\revival_tool.exe help                   :: tüm komutlar listelenir
src\tool\revival_tool.exe ifeo show              :: IFEO durumu (yoksa "yok" yazar)
src\tool\revival_tool.exe cleanup                :: idempotent, hiçbir şey kırılmaz
```

Bu dördü de sorunsuz geçtiyse, build ortamıyla bir sorun yok. Sırada
`init` veya `launch` ile gerçek deneme.
