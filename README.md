# revival

2018'de Türkiye'de kapanan bir online futbol oyununu (orijinal Anipark
yapımı, yerel olarak Joygame tarafından yayınlanmıştı) tekrar
oynanabilir hâle getirmek için yazılmış tool zinciri.

Proje iki yarımküreden oluşuyor:

1. **Client tarafı** (`src/`): Orijinal client binary'sini Themida
   packer'ı ve nProtect anti-cheat'i atlatıp çalıştırabilen tool
   zinciri. Şifreli oyun dosyalarını çözücü de burada.
2. **Server tarafı** (`server/`): Artık var olmayan sunucuların yerine
   geçen, Go ile sıfırdan yazılmış emulator (login, lobby, battle,
   patch, launcher web).

Hedef: birisi orijinal `setup.exe`'yi indirdi, tool'a gösterdi, sunucu
işini de localde açtı, oyun her iki taraftan da çalıştı.

Bu repo akademik / hobi amaçlıdır. Orijinal oyun binary'leri, asset'leri
veya sunucu kodunun hiçbir parçası burada yer almaz. Sadece kendi
yazdığımız reverse engineering araçları ve sıfırdan yazılmış server
emulator var.

## Repo yapısı

```
revival/
├── README.md, MIMARI.md, BUILD.md, LICENSE, .gitignore
├── build_all.bat               client tool zincirinin tüm bileşenlerini build eder
│
├── docs/                       genel proje belgeleri
│   ├── KULLANIM.md             CLI komutları, örnekler
│   ├── ANTI_CHEAT.md           Themida + nProtect genel bakış
│   ├── THEMIDA_BYPASS.md       Themida'yı adım adım nasıl geçtik (tutorial)
│   ├── PATCHES.md              statik binary patch listesi
│   └── DURUM.md                neyin çalıştığı, neyin açık kaldığı
│
├── src/                        CLIENT TARAFI
│   ├── tool/                   tek CLI (init, launch, extract, patch, ...)
│   ├── patcher/                Goley_.exe'ye inject edilen DLL
│   ├── wrapper/                IFEO debugger wrapper
│   └── extract/                şifreli VLH/VLD oyun dosyası çözücü
│
└── server/                     SERVER TARAFI (Go emulator)
    ├── README.md               server'a özel kullanım ve mimari
    ├── Makefile
    ├── go.mod
    ├── cmd/                    her servis için ayrı binary
    │   ├── entry-server/       login + karakter slot listesi (TCP 2270)
    │   ├── lobby-server/       oda listesi + chat (TCP 2271)
    │   ├── battle-server/      maç kurma + UDP relay (TCP 2272)
    │   ├── daum-auth/          Daum login emulasyonu (HTTP)
    │   ├── patch-server/       client update kontrolü (HTTP 80)
    │   ├── launcher-web/       MSHTML launcher sayfası (HTTP 8080)
    │   └── login-server/       eski stub, geriye uyumluluk için
    ├── internal/
    │   ├── proudnet/           Nettention ProudNet protokolünün Go portu
    │   └── common/             ortak yardımcılar (logger, hexdump)
    ├── scripts/                start-all, hosts dosyası setup vs.
    ├── web/                    launcher HTML + patch server dosyaları
    └── docs/                   protocol-notes.md
```

## Hızlı başlangıç

### Client tarafı

```bat
:: 1) Tool zincirini build et (VS 2022 Build Tools yüklü olmalı)
build_all.bat

:: 2) Joygame setup'ını tool'a göster (bir kerelik)
src\tool\revival_tool.exe init "C:\indirilenler\GoleySetup.exe"

:: 3) Client'i başlat (Yönetici olarak)
src\tool\revival_tool.exe launch
```

### Server tarafı

```bat
:: 1) Go ile build et
cd server
make build

:: 2) Hepsini aynı anda başlat
.\scripts\start-all.ps1

:: 3) Hosts dosyasını ayarla (Yönetici olarak, bir kerelik)
.\scripts\setup-hosts.ps1
```

Detaylı adımlar için `server/README.md`.

## Şu an nereye geldik

* **Client:** Themida packer'ı bypass edildi, splash ekranı görünüyor
  ("ChaguChagu V31927"). Korece "초기화중" (Yükleniyor) yazısında
  bekliyor; nProtect handshake'i için son adım açık. Detay için
  `docs/DURUM.md`.
* **Server:** ProudNet TCP framing + RMI dispatch iskeleti hazır. Mock
  client ile handshake çalışıyor. Gerçek Goley client'iyle test henüz
  yapılmadı çünkü client splash'tan ileri taşınmadı.

Yani ikisi de %80 hazır, son %20'yi bitirmek için ikisinin gerçekten
konuşturulması gerekiyor.

## Bu projenin tek CLI'si

`revival_tool.exe` client tarafını tek noktadan yönetir:

| Komut | Ne yapar |
|---|---|
| `init <setup.exe>` | Setup'ı çalıştırır, IFEO'yu ayarlar |
| `launch` | Goley_.exe başlat + patcher.dll inject + resume |
| `launch-unpacked` | unpacked_Goley_PATCHED.exe (Themida'sız yol) |
| `extract [vlh vld]` | Şifreli oyun dosyalarını aç |
| `patch <in> <out>` | Unpacked binary'e patches.json'u uygula |
| `unpack <pid>` | Çalışan Goley_'in unpacked PE memory'sini diske yaz |
| `inject <pid>` | Çalışan PID'ye patcher.dll inject et |
| `dump-threads <pid>` | Thread EIP/return-addr zincirini çıkar |
| `ifeo set/clear/show` | IFEO Debugger registry kaydını yönet |
| `cleanup` | Goley_/wrapper proseslerini öldür + IFEO temizle |
| `ping` / `help` | Sanity / yardım |

Server tarafı kendi binary'lerinden yönetiliyor (tek CLI altında
birleştirmedik çünkü ayrı ayrı daemonlar olarak çalışması daha mantıklı).

## Konfigürasyon

Hardcoded yol yok. Tool ve patcher kendi konumlarını runtime'da
hesaplıyor. Goley'in install klasörü farklıysa:

```bat
set GOLEY_INSTALL_DIR=D:\Oyunlar\Goley\BinaryTr
```

Varsayılan: `C:\Joygame\Goley\BinaryTr`.

## Belgeler

* `docs/KULLANIM.md` CLI cheatsheet (client tarafı)
* `docs/ANTI_CHEAT.md` Themida + nProtect genel bakış
* `docs/THEMIDA_BYPASS.md` adım adım tutorial
* `docs/PATCHES.md` statik binary patch listesi
* `docs/DURUM.md` şu an ne çalışıyor, ne açık
* `server/README.md` server kullanımı
* `server/docs/protocol-notes.md` ProudNet protokol notları
* `src/extract/README.md` şifre çözücü detayları

## Yapılmayanlar / kapsam dışı

* **Themida unpacker.** Bizim yöntemimiz runtime'da bypass. Offline
  unpack için Scylla/ImpRec gibi external araçlar var, biz onları
  sarmadık.
* **Eski recon script'leri.** RE sürecinde ~150 ayrı tek seferlik
  Python/PowerShell yazılmıştı. Tool zinciri olarak düzenli değildi.
  Buraya temizledik, sadece ihtiyaç olanlar geldi.
* **Resmi ProudNet kaynak kodu.** Nettention'ın malı. Sadece
  gözlemlediğimiz protokol davranışının Go re-implementation'ı var.

## Lisans

MIT (`LICENSE`).

Paketlenmiş MinHook (`src/patcher/minhook/`) BSD 2-Clause.

## İletişim

* GitHub issues: bug / öneri
* Discord: [discord.gg/5TeZP7dqcc](https://discord.gg/5TeZP7dqcc)
* X (Twitter): [@1tbssdlazim](https://x.com/1tbssdlazim)
