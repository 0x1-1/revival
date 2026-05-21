# Themida'yı nasıl geçtik

Bu yazı adım adım, hiçbir şey atlamadan, bizim Goley_.exe içindeki
Themida'yı nasıl bypass ettiğimizi anlatıyor. Hem ne yapıldığını hem
de neden o yöntemin seçildiğini görmeniz için. Böyle anti-cheat'lerle
ilk defa uğraşıyorsanız iyi bir başlangıç noktası olur.

Goley_.exe **Themida 2.x** ile pack'lenmiş (Oreans, 2014 civarı build).
Themida nedir kısaca: bir packer + anti-debug + anti-tamper.
Çalışınca PE'nin gerçek kodunu memory'de çözer, ekstra koruma katmanı
da ekler. Pratikte size karşı 5 ayrı savunma mekanizması kuruyor,
hepsini tek tek atlatmanız lazım.

## Yöntem özeti

Kısaca, Goley_.exe'ye bir DLL inject ediyoruz (`revival_patcher.dll`).
Bu DLL `DllMain`'in çalıştığı ilk milisaniye içinde:

1. Process'in kendisini öldüren API'lerin (`TerminateProcess` vs.)
   üzerine küçük stub'lar yazar. Böylece Themida "exit etmem lazım"
   kararı verse bile, exit edemez.
2. Bir Vectored Exception Handler (VEH) kurar. Themida'nın tetiklediği
   her exception artık bizden geçiyor.

Sonra arka planda çalışan bir thread, donanım breakpoint'leri (DR0)
ile Themida'nın **validation branch** noktasına nokta atışı yapar.
Themida o satıra geldiğinde, VEH `EIP`'yi success path'ine yeniden
yazar. Themida hiçbir şey patch'lendiğimizi anlamaz çünkü bellekte
hiçbir byte değişikliği olmadı.

Şu iki şey kritikti:
* **Inline armor** (DllMain içinde, async thread beklemeden).
* **Donanım breakpoint** (memory write yapmadan).

Detaylara girelim.

## Katman 1: Self-suicide engelleme

### Problem

Themida unpack'ten sonra integrity check yapıyor. Eğer Goley_'nin
kendi kodu bizim tarafımızdan kurcalanmışsa kontrol et, kurcalanmışsa
`ExitProcess` çağır. Çok kötüsü: `TerminateProcess` veya hatta direkt
syscall ile `NtTerminateProcess` çağırıp biz bir şey yapamadan kapansın.

İlk denediğimiz: hook ile bunu yakalamak. Sleep ekleyip patcher'ın
hızla çalışmasını umut etmek. Hiçbiri tutmadı. Themida unpack
**ResumeThread'den 7 milisaniye sonra** kontrol noktasına geliyor,
bizim async thread'imiz daha MinHook init bile bitirememişken.

### Çözüm: inline armor

DllMain'in içindeki kodu böyle yaptık:

```cpp
case DLL_PROCESS_ATTACH:
    // Bu bloğun tamamı DllMain dönmeden tamamlanmalı.
    // Wrapper.exe LoadLibrary çağrısından sonra ResumeThread
    // çağırıyor; ResumeThread çağırıldığında aşağıdaki bütün stub'lar
    // YERİNDE OLMALI.

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hNt     = GetModuleHandleA("ntdll.dll");

    // Bu 5 API'yi ölü nokta olarak işaretle: mov eax,1 ; ret N.
    // Yani çağrılırsa başarıyla döner ama hiçbir şey yapmaz.
    PatchStdcallStub(GetProcAddress(hKernel, "TerminateProcess"), 8);
    PatchStdcallStub(GetProcAddress(hKernel, "ExitProcess"),      4);
    PatchStdcallStub(GetProcAddress(hNt,     "NtTerminateProcess"), 8);
    PatchStdcallStub(GetProcAddress(hNt,     "RtlExitUserProcess"), 4);
    PatchStdcallStub(GetProcAddress(hNt,     "NtTerminateThread"), 8);

    // Vectored exception handler'ı da burada kuruyoruz.
    g_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
```

`PatchStdcallStub` ne yapıyor: ilgili API'nin başlangıcına şu byte'ları
yazıyor:

```
B8 01 00 00 00         mov eax, 1
C2 NN 00               ret NN          ; NN = 4*argument sayısı
```

Toplam 8 byte. Sonuç: o API'yi kim çağırırsa çağırsın, başarı dönüş
değeri alır ama gerçek işi yapmaz. Process kendini öldüremiyor.

Bu kısmı DllMain içinde yapmamız, yarışı mimari olarak kazanmak
demek. Sleep eklemekle uğraşmıyoruz; ResumeThread'den sonra Themida
ne kadar hızlı çalışırsa çalışsın, *zaten* her şey hazır.

İleride bu yöntemin önemli olduğu bir gerçek: nProtect de aynı API'leri
çağırıp process'i öldürüyor. Inline armor onu da kapsıyor.

## Katman 2: DR sweep (anti-debug)

### Problem

Themida kendi thread'lerinde `GetThreadContext` çağırıp `DR0..DR3`
register'larına bakıyor. Eğer herhangi biri sıfırdan farklıysa,
"debugger var" diyor ve intihar ediyor.

Bizim sorunumuz: validation branch'i bypass etmek için DR0'a hardware
breakpoint koymak istiyoruz. Themida bunu görür görmez bizi
öldürmesin diye, **bir kerelik kullanıp hemen temizliyoruz**.

### Çözüm: bir kerelik DR0, sonra sweep

```
1. PatchThread DR0'a 0xD3DC4D adresini yazıyor (validation branch entry).
2. Themida o adresi çalıştırır.
3. CPU EXCEPTION_SINGLE_STEP atar.
4. VEH yakalar, EIP'yi success path adresine (0xD3DCF2) yazar.
5. VEH aynı anda ClearHardwareBreakpointAllThreads() çağırır:
   process'teki tüm thread'lerde DR0..DR3'u sıfırlar.
6. Themida sonra DR sweep yapar -> hepsi sıfır, "temiz" der.
```

DR'lar process-wide değil thread-local olduğu için
`Toolhelp32Snapshot(TH32CS_SNAPTHREAD)` ile her thread'i tek tek
gezip `SuspendThread + SetThreadContext + ResumeThread` yapmak gerek.
Bu fonksiyonun tamamı `patcher.cpp` içinde `ClearHardwareBreakpointAllThreads`
adıyla var.

## Katman 3: INT3 fingerprint

### Problem

Themida ntdll wrapper'larının içine `0xCC` (INT3) byte'ları serpmiş.
Bu byte CPU'ya gelince `EXCEPTION_BREAKPOINT (0x80000003)` atar.

Eğer bir debugger varsa, o exception'ı debugger yutar (kullanıcı
"step over" der). Eğer debugger YOKSA ve VEH de yakalamıyorsa, OS
`UnhandledExceptionFilter`'a düşer ve process kapanır.

Yani Themida böyle bir mantık kuruyor: "Debugger yoksa zaten bu
exception process'i kapatır. Eğer biri bunu yutuyorsa, bu ya debugger
ya da VEH ile takip eden bir analist. İki durumda da intihar et."

### Çözüm: VEH içinde INT3'leri yutuyoruz

```c
if (code == EXCEPTION_BREAKPOINT &&
    eip >= ntdll_base && eip < ntdll_base + 0x200000) {
    exc->ContextRecord->Eip += 1;   // 0xCC instruction'ı 1 byte
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

EIP'yi 1 ileri itip "devam et" diyoruz. Themida'nın bakış açısından
INT3 sanki hiç olmamış gibi davranıyoruz. Davranışsal olarak iyi bir
debugger'a benziyoruz.

Bu kontrolu `ntdll_base` aralığında yapmak önemli; Goley_'nin kendi
kodunda da INT3 olabilir (debug build artığı falan) ve onları yutmak
istemiyoruz.

## Katman 4: Validation branch (asıl patch)

### Problem

Themida unpack sonrasında Goley_'nin kodunun içinde şu tarz bir kontrol
var:

```
cmp byte ptr [esp+13h], 0    ; eğer 0 ise fail path
jne success_path             ; değilse devam
... fail path ...
    call SuicideHandler
```

`[esp+13h]` Themida'nın runtime'da yazdığı bir flag. Eğer 0 ise,
Themida "kurcalandım" der ve fail path'e iner -> SuicideHandler ->
process ölüyor.

Memory'yi patch'leyemeyiz (tamper check). Goley_ kodunun BYTE'larına
hiçbir şekilde dokunamayız. Yine de o branch'i atlatmamız lazım.

### Çözüm: input rigging + VEH EIP rewrite

`[esp+13h]` adresine GetThreadContext ile bakıp değeri 0 olsa bile
bypass mantığı şuydu:

```
1. DR0 = validation branch'in giriş adresi (0xD3DC4D).
2. EIP oraya geldiğinde VEH tetiklenir.
3. VEH içinde *(BYTE*)(esp+0x13) = 1 yazarız. Yani Themida'nın
   beklediği flag'i doğru olarak ayarlarız.
4. Sonra normal akıştaki cmp/jne instruction'ının çalışmasına izin
   veriyoruz. Cmp 0 ile 1'i karşılaştırır, jne tetiklenir, success
   path'ine iner.
5. Hiçbir byte memory'de değişmedi, sadece stack üzerindeki bir flag.
```

Bu yöntemin güzelliği: cmp ve jne instruction'ları **GERÇEKTEN
ÇALIŞIR**. Themida bunları bypass ettiğimizi anlamaz çünkü akış
normal. Sadece girdi değerini biz hazırladık.

## Katman 5: Voluntary AV (henüz çözülmedi)

### Problem

Themida'nın son katmanı: bilerek erişilemez bir adrese yazıyor
(`mov [bad_addr], eax`). Bu `EXCEPTION_ACCESS_VIOLATION` atar.

INT3 trick'inin aynı: "Birisi bunu yutarsa debugger'dır, intihar."

### Denediğimiz çözüm (sonsuz döngü yaptı)

```c
// NAIVE -- BÖYLE YAPMAYIN
if (code == EXCEPTION_ACCESS_VIOLATION) {
    return EXCEPTION_CONTINUE_EXECUTION;  // EIP'ye dokunmadan
}
```

EIP aynı yerde kaldığı için, AV atan instruction tekrar tekrar
çalıştı. 3 saniyede 50000+ exception yakaladık. Process spin
yaparken biz kapatamadık.

### Doğru çözüm (TODO)

Instruction'un uzunluğunu hesaplayıp EIP'yi o kadar ilerletmek
gerekiyor. Bizim bundle ettiğimiz MinHook'un HDE32 disassembler'ı
zaten var, onunla yapılabilir. Henüz implement etmedik çünkü
pratikte çoğu zaman Themida bu katmana gelmeden önce paket açması
bitmiş oluyor; sıcak cache durumda nadiren tetikleniyor.

`docs/DURUM.md` içinde bu maddenin durumu var.

## Inline armor sırası neden kritikti

Bir şey karıştırmamak için açmak istiyorum:

Yanlış sıra (denedik, olmadı):
```
1. wrapper.exe Goley_'i CREATE_SUSPENDED ile spawn et.
2. wrapper.exe LoadLibraryW ile patcher.dll inject et.
3. patcher.dll yüklendi, DllMain çalıştı, **PatchThread oluşturuldu (async)**.
4. PatchThread şu aşağıdaki sırayla çalışıyor:
     a. MinHook init                          (~40 ms)
     b. Kill API stub'ları yaz                (~5 ms)
     c. VEH install                           (~1 ms)
     d. DR0 set                               (~10 ms)
5. wrapper.exe DllMain döndükten SONRA ResumeThread çağırır.
6. Goley_'nin ana thread'i çalışmaya başladı.
7. Themida unpack başlar.
```

Buradaki sorun: 5. adım 3. adımdan hemen sonra geliyor. PatchThread
4a..4d'yi tamamlamadan önce 6. adım başlıyor. Themida 7 ms içinde
kill API'yi çağırıp self-suicide yapıyor, biz daha MinHook bile
init etmemişken.

Doğru sıra (şu an ki):
```
1. wrapper.exe Goley_'i CREATE_SUSPENDED ile spawn et.
2. wrapper.exe LoadLibraryW ile patcher.dll inject et.
3. patcher.dll yüklendi, **DllMain içinde**:
     a. Kill API stub'ları yaz                (~3 ms)
     b. VEH install                           (~1 ms)
     c. ASYNC PatchThread oluştur             (background)
4. DllMain döner.
5. wrapper.exe ResumeThread çağırır.
6. Goley_'nin ana thread'i çalışmaya başladı.
7. Themida unpack başlar. Self-suicide çağırır -> stub'a düşer,
   ölü nokta. PatchThread bu sırada arka planda MinHook + DR0
   set ediyor.
```

Sıra değişikliği ile yarışı mimari olarak kazandık. Sleep eklemiyoruz,
"umarım hızlı olur" demiyoruz. Themida her şey hazır olduğunu garanti
ediyor.

## VEH ne yakalıyor (özet)

Şu an `VehHandler` içindeki davranış:

| Exception code | EIP nerede | Davranış |
|---|---|---|
| EXCEPTION_SINGLE_STEP | validation branch (0xD3DC4D) | EIP'yi 0xD3DCF2'ye yaz, DR temizle |
| EXCEPTION_BREAKPOINT  | ntdll aralığı               | EIP += 1, devam et |
| EXCEPTION_ACCESS_VIOLATION | herhangi   | (henüz doğru çözümde değil) |

## Hangi bilgi ile iş yapıldı

Böyle bir iş için başlamadan önce bilmeniz gerekenler:
* PE format ve IAT/import resolution.
* x86 instruction encoding (en azından `mov` ve `ret` için).
* `kernel32.dll` ve `ntdll.dll` içindeki "process'i öldüren"
  API'lerin tam listesi (sadece TerminateProcess yetmiyor, syscall
  versiyonları da var).
* Vectored Exception Handling vs SEH farkı.
* Windows'ta Hardware Breakpoint'lerin per-thread olduğu.
* Themida'nın ne yaptığının yüksek seviyede tarihçesi (eski Themida
  versionlarının attack surface'i hakkında forum yazıları, eski
  unpack-me CTF çözümleri).

## Test stratejisi

Her değişiklikten sonra:
1. `revival_tool cleanup` (eski instance'ları öldür).
2. `revival_tool launch`.
3. `patcher.log`'u izle.
4. Beklenen kritik satırlar:
   - `DLL_PROCESS_ATTACH` (8 ms içinde)
   - `Patched [inline] kernel32!TerminateProcess`
   - `Patched [inline] ntdll!NtTerminateProcess`
   - `[inline] VEH installed`
   - `PatchThread starting`
   - `MinHook: CreateProcessA/W hooks ACTIVE`

Yukarıdakileri görüyorsan inline armor çalışıyor demektir. Goley_
30+ saniye yaşayabiliyorsa Themida'yı geçtin demektir; sonrası
nProtect ve onun handshake'i (bkz: `ANTI_CHEAT.md`).

## Sürprise olabilecek noktalar

* **Loader Lock**. DllMain içinde gerçekte ne kadar iş yapabilirsiniz?
  VirtualProtect + memcpy + AddVectoredExceptionHandler yapıyoruz.
  Bunlar loader lock ile çatışmıyor; deadlock yok. Fakat örneğin
  `LoadLibrary` çağırsaniz deadlock garanti. Inline armor içinde
  bu sebeple `GetModuleHandle` kullanıyoruz, `LoadLibrary` değil.
* **Wow64**. Goley_ 32-bit, host Windows 64-bit. Dump-threads veya
  patcher araçlarını 64-bit derlerseniz `GetThreadContext` Wow64
  syscall frame'ini döner, 32-bit user state'i değil. Hepsini x86
  derlemek en temizi.
* **IFEO recursion**. nProtect "trusted re-launch" pattern'i ile
  Goley_'i tekrar spawn ediyor. IFEO Debugger kaydımız olmasaydı
  o child'a inject etmeyi kaçırırdık. wrapper.exe environment var
  ile recursion'ı bozarak hem inject yapıyor hem sonsuz döngü
  olmuyor.

Bu yazının amacı sizin de böyle bir bypass'i yapmanıza yetecek bilgi
vermek. Adımları üzerine tartışıp iyileştirebilirsiniz. Soru için
GitHub issues'a ya da Discord'a yazın.
