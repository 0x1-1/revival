# Anti-cheat genel bakış

Goley_.exe iki ayrı korumayla geliyor: dış kabukta **Themida 2.x**,
iç katmanda **INCA nProtect GameGuard**. Bu iki sistem birlikte
çalışmak üzere tasarlanmış değil; üst üste binince ikisinin de
ayrı ayrı geçilmesi gerekir.

Bu yazı her bir katmanın ne yaptığını ve bizim ona karşı ne yaptığımızı
anlatıyor. Bypass detayının tam adım adım anlatımı ise
`THEMIDA_BYPASS.md` içinde.

## Themida 2.x

Oreans'ın 2014 civarında yayınladığı bir packer. Beni şaşırtan kısmı
"packer" demenin yetersiz olması: dış kabuk + 5-6 farklı anti-debug
mekanizması + anti-tamper bir bütün olarak geliyor.

Bizim Goley_'de takıldığımız mekanizmalar:

* **Anti-tamper.** Unpack sonrası kendi kod sayfalarını SHA hash'liyor.
  Themida'nın koruduğu bölgede tek byte değişirse, 5 saniye sonra
  process suicide yapıyor. Bu yüzden hiçbir zaman memory patch yapmıyoruz.
* **Anti-debug, DR sweep.** GetThreadContext ile DR0..DR3 register'larını
  okuyup hepsinin sıfır olmasını bekliyor. Sıfır değilse "debugger
  var" deyip çıkıyor.
* **Anti-debug, INT3 fingerprint.** ntdll wrapper'larının içine
  `0xCC` byte'ları serpilmiş. Debugger yokken bunlar
  `EXCEPTION_BREAKPOINT` atar; eğer biri yutuyorsa Themida onu da
  "debugger var" olarak yorumlar.
* **Anti-debug, voluntary AV.** Bilerek erişilemez adrese yazıyor.
  `EXCEPTION_ACCESS_VIOLATION` atar; INT3 trick'inin aynı.
* **ResumeThread'e karşı yarış.** Themida unpack ResumeThread'den
  ~7 ms sonra başlar. Bypass kodumuzu o süreye sığmak zorundayız.

Hepsinin nasıl çözüldüğü `THEMIDA_BYPASS.md` içinde tek tek var.
Kısaca:

* DllMain'in içine **inline armor** koyduk (kill API stub + VEH).
  Böylece yarışı mimari olarak kazandık, sleep'lerle uğraşmıyoruz.
* DR0 ile validation branch'ine bir kerelik hardware breakpoint
  koyup VEH'de EIP'yi success path'ine yazıyoruz. Sonra DR'ları
  sweep'liyoruz.
* INT3'leri VEH içinde EIP+1 ile yutuyoruz (ntdll aralığında).
* Voluntary AV hala açık (low priority, çoğu zaman tetiklenmiyor).
  Çözümü HDE32 ile instruction length advance, henüz implement
  etmedik.

## INCA nProtect GameGuard (CC2 jenerasyonu)

Kore yapımı, eski jenerasyon (CC2, ~2010-2014). Şu dosyalardan
oluşuyor:

```
GameGuard/
    GameMon.des      ; arka planda çalışan ana daemon
    npggNT.des       ; NT kernel hook (driver)
    npsc.des         ; sistem tarama
    ggscan.des       ; bellek tarama
    ggerror.des      ; hata dialog'ları
```

Bizim için şanslı bir gerçek: Goley'in install klasöründe
`GameGuard.disabled/` adlı bir klasör var. Yani bu dosyalar orijinalde
oradaydı ama biri (Joygame? veya bizden önceki bir denemeci?) onları
"disabled" hale getirmiş. nProtect bunları açmaya çalışınca bulamıyor
ve hata moduna giriyor.

Bizim ise iki şey düzeltmek: o hata modu sonucu çıkan dialog ve
o hata modu sonrası exit. Bunu iki binary patch ile yapıyoruz
(`unpacked_Goley_.exe` üzerinde). Detay için `PATCHES.md`.

### nProtect bypass çalışmakta olan kısmı

`patches.json` içinde iki patch var:

* **P-1**: Error reporter fonksiyonun prologue'unu `xor eax,eax; ret 4`
  ile değiştir. `if (strlen(error_buf)) MessageBoxA(...)` no-op
  olur, hiçbir dialog görünmez.
* **P-2**: nProtect event callback fonksiyonun prologue'unu
  `mov eax,1; ret 8` ile değiştir. Her event "success" döner,
  hiçbir error mesajı ne buffer'a yazılır ne flag sıfırlanır.

Bu iki patch'le unpacked binary 26 MB'tan 42 MB'a kadar init ilerletti,
ama hala bir noktada takılıyor. Büyük olasılıkla `WaitForSingleObject`
seviyesinde, nProtect'in normalde GameMon'dan beklediği bir "ready"
event'inde.

### Bypass'ın çalışmayan kısmı

Şöyle bir tablo: nProtect kütüphanesi sadece error callback değil,
gerçek işleyişi de yapıyor. Kaç yerde `WaitForSingleObject` çağrısı
olduğunu sayınca 94 çıktı. Bunlardan biri gerçekten kritik (init
thread'in beklediği handle), gerisi yan kod. O kritik wait'i bulmak
için mevcut PID'e attach edip `dump-threads` ile EIP'yi okuyup IDA'da
incelemek lazım. Büyük iş değil, sadece zaman istiyor.

## Özet

```
                    KORUMALAR                 BIZIM BYPASS
                    ---------                 ------------
KATMAN 1: Themida 2.x
  Anti-tamper                                memory patch hiçbir zaman
  DR sweep                                   bir kerelik DR0, hemen sweep
  INT3 fingerprint                           VEH içinde EIP+1
  Voluntary AV                               TODO (HDE32 instr-length)
  ResumeThread yarışı                        inline armor (DllMain'de)

KATMAN 2: nProtect
  Error MessageBox dialog'ları               P-1: error fn no-op
  Init flag sıfırlama                        P-2: event callback "success"
  GameMon handshake bekleme                  TODO (DURUM.md'a bak)
```

İki katmanı da geçip splash'a kadar geldikten sonra hala
ProudNet handshake var. O kısmı `server/` altındaki Go emulator
ile çözüyoruz (network emulasyonu).
