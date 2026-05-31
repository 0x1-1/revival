# Binary patch'ler

`unpacked_Goley_.exe`'ye uyguladığımız statik patch'lerin tam listesi.
Tool içindeki `tool/patches.json` bu belgenin makine okunabilir hali;
biri değişirse diğerini de senkron tutun.

Adresler standart PE `ImageBase = 0x00400000` varsayar.

## P-1: GameGuard error reporter prologue'u

| | |
|---|---|
| Hedef | `sub_D393F0` (RVA `0x935666`) |
| Ne iş yapıyordu | `if (strlen(error_buf)) MessageBoxA(...)` |
| Original byte'lar | normal x86 prologue: `55 8B EC ...` |
| Yeni byte'lar | `33 C0 C2 04 00` |
| Mnemonic | `xor eax,eax ; ret 4` |
| Etki | Hiçbir error dialog'u görünmüyor. Fonksiyon 0 döner (success). |
| Risk | Yok. Fonksiyonun caller'ı için gerekli başka bir yan etkisi yoktu. |

Neden önemli: nProtect dosyaları `GameGuard.disabled/` altında
olduğu için GG init fail edip bu fonksiyon "Error 153" gibi
mesajları patlatmaya çalışıyordu. Fonksiyonu ölü nokta yapmak
dialog'ları tamamen susturuyor.

## P-2: nProtect event callback her zaman success

| | |
|---|---|
| Hedef | `sub_D35720` (RVA `0x935720`) |
| Ne iş yapıyordu | nProtect event'leri için switch table |
| Original byte'lar | `55 8B EC 8B 45 08 05 17 FC FF FF 83 F8 12 ...` |
| Yeni byte'lar | `B8 01 00 00 00 C2 08 00` |
| Mnemonic | `mov eax,1 ; ret 8` |
| Etki | Her event success rapor eder. Error buffer'a yazma yok. Init flag sıfırlama yok. |
| Risk | Kod 1019 success case'inde küçük bir housekeeping vardı (sub_A7AC00). Atlanması pratikte sorun yaratmadı. |

Orijinal kod şöyle bir switch'ti:

```
case 1001..1006, 1011..1015:    // hata kodları
    error_buf'a yaz
    init_flag = 0
    return 0

case 1018:
case 1019:
    return 1   // başarı
```

Switch'in tamamını "success" literali ile kısa devre etmek en basit
yol. Memory'de byte değişikliği yapıyoruz ama Themida dışındaki
bir kodda; nProtect anti-tamper bizi görmüyor.

## P-3: nProtect event dispatcher (GERİ ALINDI, UYGULAMA)

| | |
|---|---|
| Hedef | `sub_8E70E0` (RVA `0x4E70E0`) |
| Denenen yeni byte'lar | `B8 01 00 00 00 C2 0C 00` (mov eax,1; ret 12) |
| Sonuç | Working Set 42 MB'tan 26 MB'a geriledi |
| Sebep | Bu fonksiyon sadece nProtect translator değildi, içinde yasal init kodu da vardı (event counter setup, internal state). Stub'lamak onları da kapsadı, ilerleme geriye gitti. |
| Durum | `patches.json` içindeki `reverted_patches` listesinde. Aynı problemi daha cerrahi bir patch ile çözmek (mesela sadece içindeki sub_D35720 çağrılarını NOP'lamak) açık bir iş. |

Yani: bir patch'in "her zaman 1 döner" hali her durumda doğru
cevap değil. Kontrol etmeden uygulamayın. Working Set değişimine
bakmak iyi bir gösterge: artıyorsa init ilerliyor, geriliyor veya
aynı kalıyorsa over-patch yaptınız demektir.

## Şu anki güvenli set

* P-1: 5 byte, `0x00935666` adresinde
* P-2: 8 byte, `0x00935720` adresinde

**Toplam: 13 byte**

Bu 13 byte ile unpacked binary 26 MB takılma yerine 42 MB'a kadar
init ilerletiyor. Splash'a hala ulaşamadı (bkz: DURUM.md), o yüzden
ihtimal P-4, P-5 vs. eklenecek.

## Patch nasıl uygulanıyor

`apply_patches.py` standalone Python script'i:

1. `patches.json` içindeki listenin üzerinden geçiyor.
2. Her entry için PE section table'ı kullanarak `addr` (mutlak VA)
   değerini file offset'e çevirir (RVA = VA - ImageBase, sonra section
   header'larına bakıp raw offset hesabı).
3. Input binary'i hedef path'e kopyalar, sonra file offset'e patched
   byte'ları yazar.

IDA Pro veya başka bir RE aracı gerekmez. Sadece Python + JSON.

`revival_tool patch <in> <out>` arka planda `apply_patches.py`'yi
çağırıyor. Aynı işin ucuna kadar:

```bat
python tool\apply_patches.py --src in.exe --dst out.exe
```

## Yeni patch eklemek

1. Hedef binary'de bypass etmek istediğiniz fonksiyonu bulun. Bunun
   için IDA Pro veya benzeri bir disassembler iyi olur. (Tool zinciri
   IDA gerektirmiyor, ama yeni patch için manuel analiz kaçınılmaz.)
2. Original ve patched byte'ları belirleyin.
3. `tool/patches.json` içine yeni entry ekleyin:

   ```json
   {
       "id":       "P-N",
       "name":     "kısa açıklama",
       "addr":     "0x00XXXXXX",
       "size":     N,
       "comment":  "neden bu patch?",
       "patched":  "BYTE'LAR_HEX"
   }
   ```

4. `docs/PATCHES.md`'a (bu dosyaya) yeni bir bölüm ekleyin.
5. Test: `tool\revival_tool.exe patch in.exe out.exe && launch-unpacked`.
6. Working Set'i izleyin. Önceki bilinen iyi değerden düştüyse,
   patch'i geri alın (P-3 hatası).

## Ders çıkarmış olan kısım

* **Memory patch'i için güvenli bölge:** Themida'nın koruduğu
  binary'lere ASLA. Sadece unpacked dump'a yazmak (veya dynamic
  bypass için VEH + HW BP).
* **"Always success" patch'ini test etmeden uygulamak yanlış.**
  Fonksiyon legitimate iş yapıyor olabilir.
* **Working Set büyümesi iyi gösterge:** allocation ilerliyor demek;
  yani init pipeline'ı bir sonraki adıma geçiyor. Aksi takdirde
  takılma noktası geri kayıyor demektir.
