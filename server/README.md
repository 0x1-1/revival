# Server (emulator)

Goley'in artık var olmayan sunucularının yerini tutan, Go ile sıfırdan
yazılmış emulator. Hedef: orijinal Goley client'ini (açabildiğimiz
kadarıyla) bizim sunuculara yönlendirmek, login + lobby + maça giriş
zincirinin client tarafından açılan TCP/UDP çağrılarının karşılığını
vermek.

Bu ağacın tamamı Anipark'ın **ProudNet** (Nettention) network stack'inin
gözlemlediğimiz protokol davranışının Go'da yeniden inşası. Resmi
ProudNet kod tabanı kullanmıyoruz; sadece public sample uygulamalarını
(`Sample`, `Simple`, `CasualGame2`) ve Goley client'inin runtime
trafiğini inceleyip ortaya çıkardığımız davranışı modelliyoruz.

## Bileşenler

| Servis | Default port | Ne yapar |
|---|---|---|
| `entry-server` | 2270 (TCP) | Login, karakter slot listesi |
| `lobby-server` | 2271 (TCP) | Oda listesi, oda kurma, lobby chat |
| `battle-server` | 2272 (TCP) + UDP relay | Maç kurma, P2P NAT hole punching relay |
| `daum-auth` | HTTP | Eski Daum hesap login emulasyonu (Joygame TR için) |
| `patch-server` | HTTP/80 | Client'in update kontrolü için; PatchInfo.bin + HashV2.VLL servisi |
| `launcher-web` | HTTP/8080 | MSHTML WebView'ın açtığı launcher HTML sayfası |
| `login-server` | TCP/2270 | (Eski stub; entry-server'ın atası, hala bulunsun diye) |

Her servis ayrı bir Go binary. `cmd/<servis>/main.go` içinde kendi
giriş noktası var. Ortak network kodu `internal/proudnet/` altında.

## Hızlı başlangıç

### 1) Gereksinimler

* **Go 1.22+**: `winget install GoLang.Go` ya da https://go.dev/dl/
* Orijinal Goley client'i `C:\Joygame\Goley\` altında (patch server'in
  servis ettiği binary'ler senin gerçek install'undan beslenir, bkz
  aşağısı).

### 2) Build

```bat
cd server
make build
```

Veya manuel:

```bat
go build -o bin/ ./cmd/...
```

`bin/` altında her servisin .exe'si oluşur.

### 3) Çalıştır

Bir defada hepsi (ayrı pencerelerde):

```bat
.\scripts\start-all.ps1
```

Veya tek tek:

```bat
.\bin\entry-server.exe       :: port 2270
.\bin\lobby-server.exe       :: port 2271
.\bin\battle-server.exe      :: port 2272 + UDP
.\bin\daum-auth.exe          :: HTTP (Daum login emulasyonu)
.\bin\patch-server.exe       :: port 80
.\bin\launcher-web.exe       :: port 8080
```

### 4) hosts dosyası

Client orijinal Joygame DNS isimlerini çözmeye çalışıyor. Bizi
göstermeleri için Windows hosts dosyasına yönlendirme ekleyin (Yönetici
olarak):

```bat
.\scripts\setup-hosts.ps1
```

Test sonrası geri al:

```bat
.\scripts\restore-hosts.ps1
```

setup-hosts.ps1 şu girişleri ekliyor:

```
127.0.0.1   cdn.joygamedl.com
127.0.0.1   joygame.com
127.0.0.1   www.joygame.com
```

### 5) Patch server için orijinal binary'ler

`web/launcher/chagu/Real_Server_Patch/` altında iki dosya var
(`HashV2.VLL`, `PatchInfo.bin`). Bunlar bizim üstlerine yazdığımız
stub'lar. Client gerçek update check yaptığında buradaki
`Goley.exe`'yi de hash'lemek istiyor. O dosyayı kendi Goley
install'unuzdan (`C:\Joygame\Goley\Goley.exe`) buraya kopyalamanız
lazım:

```bat
copy "C:\Joygame\Goley\Goley.exe" web\launcher\chagu\Real_Server_Patch\Goley.exe
copy "C:\Joygame\Goley\LauncherRestarter.exe" web\launcher\chagu\Real_Server_Patch\LauncherRestarter.exe
```

Repo'ya commit etmiyoruz çünkü orijinal Joygame binary'leri telif
sahibinin malıdır.

## Tasarım notları

### ProudNet protokol katmanı

`internal/proudnet/` içinde:

* `framing.go`: TCP framing (uzunluk-önek + RMI ID). Bu katman hâlâ
  scaffold durumunda; gerçek byte layout ve handshake client canlı TCP
  aşamasına ulaşınca doğrulanacak. Güncel statik bulgular için
  `C:\Joygame\goley-rev\notes\faz15-rmi-static.md`.
* `message.go`: PIDL serializer/deserializer. Goley'in kullandığı
  primitive tipleri (string, int32, GUID, bytes) okuyup yazıyor.
* `rmi_ids.go`: tüm RMI method ID'lerinin listesi. CasualGame2
  sample'ından miras alındı + Goley-specific RPC'ler eklendi:
  `RequestLogin`, `NotifyLoginOk`, `GotoLobby`, `GotoGameRoom`.
* `server.go`: TCP listener + per-connection goroutine + handler
  registry. `s.Handle(RMI_ID, fn)` ile route eklersin.
* `udp_relay.go`: P2P NAT hole punching için UDP relay. Client'lar
  birbirleriyle doğrudan UDP konuşamayınca biz buradan paketleri
  yönlendiriyoruz.

### Servis modelleri

CasualGame2 sample'ı ile birebir aynı patern'i izliyoruz:

```
client ──TCP──> entry-server (login)
                     │
                     │  NotifyLoginOk + token
                     ▼
client ──TCP──> lobby-server (oda listesi, chat)
                     │
                     │  GotoGameRoom + roomGuid
                     ▼
client ──TCP+UDP──> battle-server (maç)
```

`entry-server` login doğrulamasını şu an "her zaman başarılıyor"
olarak yapıyor (gerçek bir kullanıcı DB'si yok). Token üretip döndürür.

`lobby-server` token kontrol ediyor (eğer entry'de üretildiyse kabul),
oda listesi/oda kurma/lobby chat'ı emule ediyor.

`battle-server` GotoGameRoom geldiğinde bir room kurar, client'lar
TCP üzerinden sync olur, P2P için UDP relay'i devreye sokar.

### Client tarafı RE ne dedi

Goley'in match logic'i **client-side**. Yani gerçek oyun mantığı
client'ların kendi arasında P2P sync ile akıyor. Server sadece:

1. Authentication (login).
2. Matchmaking (kim hangi maça girecek).
3. Relay (P2P olmazsa packet forwarding).

Bu bizim işimizi kolaylaştırıyor çünkü server tarafında maç fiziğinin
ya da oyun kurallarının implementasyonunu yapmamız gerekmedi.

Daha detay için `docs/protocol-notes.md`.

## Durum

| Bileşen | Durum |
|---|---|
| ProudNet TCP handshake | Scaffold; gerçek client ile henüz doğrulanmadı |
| RMI dispatch | İskelet; `RequestLogin=0x259`, `NotifyLoginOk=0x28b`, `NotifyLoginFailed=0x28c` statik doğrulandı |
| Entry server (login) | Stub: her login başarılı |
| Lobby server | İskelet, oda listesi sabit |
| Battle server | İskelet, UDP relay var |
| Daum auth | İskelet |
| Patch server | HashV2.VLL + PatchInfo.bin servis ediyor |
| Launcher web | Cached HTML servis ediyor |
| Client bağlantı | Henüz doğrulanmadı (client'i Themida + nProtect'ten geçirip splash'tan ileri taşımadık) |

Client tarafındaki Themida + nProtect bypass durumu için ana
repo'daki `docs/DURUM.md`'a bakın.

## Loglar

Her servis `slog` ile stdout'a JSON benzeri yazı loguyor. Verbose moda
geçmek için:

```bat
set GOLEY_LOG_LEVEL=debug
.\bin\entry-server.exe
```

## TODO

* [ ] Gerçek bir kullanıcı DB ekle (SQLite yeter)
* [ ] Lobby oda listesini kalıcı hale getir
* [ ] Battle server'da maç state recording (replay için)
* [ ] Daum auth'u tam emule et (Joygame'in eski OAuth akışı)
* [ ] Patch server'ı CDN cache mantığıyla bağ (orijinal Joygame
      patch fingerprint'i ile uyumlu hash üret)
* [ ] Client gerçekten bağlandığında packet log'larını gerçeklikle
      kıyasla (bizim mock client testlerinden farklı olabilir)

## Notlar

* Bu sunucu **offline / private use için**. Joygame'in resmi
  sunucularıyla rekabet etmek ya da onların yerine ücretli hizmet
  vermek gibi bir niyetimiz yok.
* ProudNet protokolü Nettention'ın. Burada sadece gözlemlediğimiz
  davranışın re-implementation'ı var. Resmi ProudNet kaynak kodu
  veya binary'si bu repoda yok.
* `web/launcher/index.html` Joygame'in launcher'inin cache'lenmiş
  HTML'i. Eski sayfa zaten DNS'ten düştüğü için yenisi yok.
