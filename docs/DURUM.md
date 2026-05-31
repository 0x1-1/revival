# Proje durumu

Bu sayfa neyin çalıştığını ve neyin beklediğini günü gününe tutuyor.
Son güncelleme: 2026-05-21.

## Çalışan kısımlar

* **Server tarafı**: Go ile yazılmış 6 servis (entry/lobby/battle/
  daum-auth/patch/launcher-web). ProudNet TCP framing + RMI dispatch
  iskeleti hazır. Mock client ile handshake doğrulandı. Gerçek Goley
  client'iyle test henüz yapılmadı çünkü client splash'tan ileri
  taşınmadı.
* Build sistemi: tool, patcher DLL ve wrapper tek bir `build_all.bat`
  ile derleniyor. Yollar hardcoded değil, exe'nin kendi konumundan
  hesaplanıyor.
* `revival_tool` CLI: init, launch, launch-unpacked, extract, patch,
  unpack, inject, dump-threads, ifeo (set/clear/show), cleanup, ping,
  help. Hepsi çalışıyor.
* **Yol A (canlı Themida bypass):** splash görünene kadar geliyor.
  Goley_ 80+ saniye yaşıyor, "ChaguChagu V31927" yazısı görünüyor,
  Korece "초기화중" (Yükleniyor) yazısı sabit kalıyor. Sonrası açık.
* Inline armor (race fix): DllMain içinde kill API stub'ları + VEH
  kuruluyor. ResumeThread öncesi her şey hazır. `Sleep` ile uğraşılmıyor.
* Themida INT3 swallow (ntdll): VEH içinde EIP+1 ile yutuluyor.
* Themida validation HW BP rewrite + DR sweep: tek seferlik DR0,
  hit sonrası DR0..3 her thread'de temizleniyor.
* nProtect MessageBox suppression (runtime, DLL ile): IAT hijack +
  HW BP kombinasyonu ile.
* **Yol B (statik patch unpacked binary'e):** binary 42 MB Working
  Set'e kadar geliyor, hiçbir dialog çıkmıyor, ama pencere açılmıyor.
* P-1 ve P-2 statik patch'ler doğrulandı.
* VLD/VLH çözücü (`extract/decrypt.py`): bütün Anipark şifreli
  oyun dosyalarını açıyor (karakterler, stadyumlar, çeviriler).
  Türkçe çeviri tam, Çince Joygame tarafından dahil edilmemiş.

## Bloke olan kısımlar

### Yol A: nProtect handshake event'ini bekliyoruz
Inline armor + Themida bypass + nProtect MessageBox suppression
sonrası Korece splash görünüyor ve process 80+ saniye yaşıyor. Ama
init thread'in beklediği bir event hiç gelmiyor. Bu event'i normalde
gerçek `GameMon.des` daemon signal ederdi, biz daemon'i runtime'da
çalıştırmadığımız için event yok.

Bir sonraki adım: patcher.dll'e `WaitForSingleObject` hook ekleyip
hangi handle'ın beklediğini logla (NtQueryObject ile handle adı).
Tespit edildikten sonra kendi DLL'imizden `SetEvent` ile signal et.

### Yol B: 42 MB Working Set sonrası pencere yok
Patches P-1 + P-2 ile process 26 MB takılmaktan 42 MB'a kadar
ilerledi, daha sonra hiçbir şey olmuyor. Pencere açılmıyor.
IAT sağlıklı (CreateWindowExW vs. resolve edilmiş) ama o API'ler
hiç çağrılmıyor demek ki kod o noktaya gelmiyor.

Bir sonraki adım: takılan PID'e `dump-threads` çek, EIP cluster'ına
bak. Büyük ihtimalle `WaitForMultipleObjects` çağrılarının olduğu
0x8E4A9C..0x8E5BEF aralığında (nProtect handshake wait noktaları
için sağlam aday).

### Themida voluntary AV bypass (low priority)
Naive "swallow all" yaklaşımı infinite loop yaptı (50000+ exception
3 saniyede). Doğru çözüm HDE32 ile instruction length advance.
İmplementasyonu zor değil, ama her iki yolda da bloke değil; çoğu
zaman Themida bu katmana gelmeden önce unpack bitmiş oluyor. Sıcak
cache durumunda bazen tetikleniyor.

## Bilinmeyenler

* Yol A için asıl takıldığımız `WaitForSingleObject` site'i hangi
  çağrılardan biri. 94 çağrı site'i var, biri kritik.
* nProtect handshake event'i kernel handle mı (SetEvent ile çözeriz)
  yoksa memory-mapped synchronization primitive mi (farklı yöntem
  gerek).
* Server emulator network handshake'ini yeterince iyi konuşabilse
  bile, Yol A veya B network koduna ulaşınca client gerçekten
  bağlanacak mı.

## Son dönemde tamamlananlar

* Inline armor mimari fix: race koşulu yapısal olarak çözüldü,
  Sleep tuning ile değil.
* Themida INT3 swallow VEH'e eklendi.
* Statik patch'ler P-1 + P-2 doğrulandı: 26 MB -> 42 MB Working
  Set ilerlemesi var.
* P-3 attempt + revert (over-patch).
* Tüm eski PowerShell helper'ları tek bir `revival_tool` CLI'sında
  birleştirildi.
* `revival_tool init` ile setup'tan başlayıp launch'a kadar olan akış
  tek komuta toplandı.
* Hardcoded yollar kaldırıldı; exe konum + environment variable
  ile dinamik resolve.
* VLD çözücü Python script'i + binary blob (`goley_real_code.bin`)
  repoya commit edildi.
* Server tarafı goley-server'dan repo'ya entegre edildi.

## Server tarafı TODO

* [ ] Gerçek kullanıcı DB (SQLite yeter)
* [ ] Lobby oda listesini kalıcı hale getir
* [ ] Battle server'da maç state recording (replay için)
* [ ] Daum auth'u tam emule et (eski OAuth akışı)
* [ ] Patch server'i CDN cache mantığıyla bağ (hash fingerprint uyumu)
* [ ] Client gerçekten bağlandığında packet log'larını gerçeklikle
      kıyasla; mock client testleri eksikleri kaçırabilir

## Client tarafı TODO

* [ ] `WaitForSingleObject` hook ile handle ismini logla (Yol A için
      en kritik adım).
* [ ] Tespit edilen handle'ı `SetEvent` ile signal et, splash'tan
      sonra Goley_'i devam ettir.
* [ ] Cerrahi patch ile `sub_8E70E0` içindeki `sub_D35720` çağrısını
      NOP'la (Yol B için aşağı indirme alternatifi).
* [ ] HDE32 instruction-length advance ile voluntary AV swallow.
* [ ] `revival_tool unpack` için import table reconstruction ekle
      (Scylla benzeri); şu an raw memory dump alıyor, IAT fix yok.
* [ ] Bir config dosyası ekle (paths.ini gibi), environment variable
      yerine.
