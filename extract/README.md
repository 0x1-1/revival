# extract

Goley'in şifreli oyun dosyalarını (`.VLH` + `.VLD` çift'leri) açan
Python script'i. Goley `C:\Joygame\Goley\Data\` altında bütün karakter
modellerini, stadyum dosyalarını, shader'ları ve çevirileri bu formatla
tutuyor.

## Hızlı kullanım

Önce Unicorn'u kur (tek seferlik):

```
pip install -r requirements.txt
```

Sonra:

```
:: Tek bir çifti aç
python decrypt.py "C:\Joygame\Goley\Data\Character.VLH" "C:\Joygame\Goley\Data\Character.VLD" --out extracted

:: Veya Data klasörünün tamamını bir kerede aç
python decrypt.py --all "C:\Joygame\Goley\Data" --out extracted
```

`extracted/` altında her çift kendi alt klasöründe açılır
(`extracted/character/`, `extracted/stadium/`, ...).

`revival_tool extract` komutu da arka planda bu script'i çağırıyor.

## Cipher hakkında

Anipark Goley için kendi yazdığı bir cipher kullanmış. Bir TEA delta
sabiti var, Blowfish tarzı 256 girişli iki S-box'ı var, 16-byte
blok'larda çalışıyor.

Cipher'i tam reverse edip Python'a portlamak yerine, daha emin bir yol
seçtik: Goley'in kendi decrypt fonksiyonunu memory dump'tan
(`goley_real_code.bin`, 1.7 MB) okuyup Unicorn x86 emulator'de
çalıştırıyoruz. Böylece Anipark'ın cipher'ında bir buffer overflow ya
da edge case varsa biz de aynısına takılıyoruz. Yani output ne ise
oyun'un kendi runtime'ında gördüğü de o.

Cipher detayları:
* Master anahtar (bütün VLH'ler için sabit):
  `MD5("VolanteEncryptKey_84106141")`
* Her VLH'in içinde 16 byte uzunluğunda ASCII bir anahtar var (dosyaya
  göre farklı). Mesela Character.VLH'in anahtarı Stadium.VLH'inkinden
  farklı.
* O ASCII anahtarın MD5'i, aynı VLD dosyasını çözmek için kullanılır.
* VLD'nin içinde arka arkaya zlib stream'leri var; her stream bir
  dosya. Dosya isimleri VLH index tablosunda yazılı.

## Akış

```
+----------------+         +----------------+
| Character.VLH  |         | Character.VLD  |
+----------------+         +----------------+
        |                          |
        | MD5("VolanteEncryptKey   |
        |   _84106141") ile çöz    |
        v                          |
+----------------+                 |
| index tablosu  |                 |
+----------------+                 |
        |                          |
        | ilk 16 byte ASCII anahtar|
        |                          |
        +--- MD5 ---> + VLD anahtarı --+
                                       |
                                       v
                              +----------------+
                              | zlib stream'ler|
                              | (her biri 1   |
                              |  dosya)        |
                              +----------------+
                                       |
                                       v
                              extracted/character/
                                  Mascot.X
                                  Player001.X
                                  ...
```

## `goley_real_code.bin` nereden geldi

Goley_.exe Themida ile pack'lendiği için disk'teki binary'de decrypt
fonksiyonu okunamıyor. RE aşamasında Goley_'i runtime'da bizim
patcher.dll ile çalıştırdık, Themida unpack'i bitirdikten sonra
memory'den 0x00400000-0x00580000 aralığını diske yazdık. Bunun içinde
0x4194c0'da `key_schedule` ve 0x4185f0'da `decrypt_block` fonksiyonları
sırayla var.

Bu dosya repoya commit edilmiş durumda (binary blob), kullanıcının
kendi unpack işlemi yapması gerekmiyor. Sadece IDA ile inceleyip
fonksiyon adreslerini doğrulamak istersen açabilirsin (32-bit PE
*değil*, raw memory dump, IDA'da "Load file" > "Binary file" + image
base 0x401000).

## Çıkan dosyalardan örnekler

```
extracted/character/
    Mascot.X
    Player_001.X
    ...
extracted/stadium/
    Stadium_TR.X
    Stadium_Tutorial.X
    ...
extracted/translations/
    Korean.txt
    Turkish.txt        <-- Türkçe çeviriler
    Chinese.txt        <-- Çince boş (Joygame Türkiye'ye Çince
                           dahil etmemiş)
    ...
```

`Turkish.txt` içinde menü yazılarından oyun içi hata mesajlarına kadar
Joygame'in Türkçe versiyonunda kullandığı her şey var. Server emulator
yazarken bu çevirileri kullanıyoruz.
