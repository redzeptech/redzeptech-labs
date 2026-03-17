# Kaspersky İstisna Ekleme Rehberi

Bu proje bir **adli bilişim ve siber güvenlik laboratuvarıdır**. `generate_eicar.py` ve diğer test scriptleri, antivirüs tespit yeteneklerini sınamak için kasıtlı olarak EICAR gibi standart test imzaları oluşturur. Bu dosyalar **zararlı yazılım değildir**.

Projeyi başka bir bilgisayara taşıdığınızda veya Kaspersky kurulumu yaptığınızda, aşağıdaki adımları uygulayarak bu klasörü istisna listesine ekleyin. Böylece `generate_eicar.py` çalıştığında Kaspersky müdahale etmez.

---

## Neden Parçalı/Şifreli Yöntem İşe Yarar?

Kaspersky gibi antivirüsler, dosyaları tararken **bilinen zararlı dizilerini** arar:

| Yöntem | Kaspersky ne görür? | Sonuç |
|--------|----------------------|-------|
| **Açık metin** | `EICAR-STANDARD-ANTIVIRUS...` dizisini görür | BLOCK! |
| **Şifreli/Parçalı metin** | `['X5O!', 'P%@AP[', ...]` gibi anlamsız parçalar görür | PASS! |

`generate_eicar.py` EICAR string'ini parçalara bölüp çalışma anında `"".join()` ile birleştirir. Statik tarayıcı kaynak kodda tam imzayı bulamadığı için script engellenmez.

---

## 3. Adım: Eğer Hala Yakalanırsa (Bellek Taraması)

Dosya oluşturulurken hâlâ yakalanıyorsa, Kaspersky **AMSI (Antimalware Scan Interface)** üzerinden belleği tarıyor olabilir. Bu durumda script'e şu eklemeler yapıldı:

- **`time.sleep(2)`** — Bazı antivirüsler çok hızlı dosya yazımından şüphelenir; kısa gecikme bu tetiklemeyi azaltabilir
- **bytearray ile yazma** — Veri önce `bytearray` içine alınır, sonra diske yazılır; bu akış bazı bellek tarayıcılarını atlatabilir

---

## Adımlar

### 1. Kaspersky Ayarlarını Aç

Kaspersky uygulamasını açın ve **Ayarlar** (Settings) bölümüne gidin.

### 2. Güvenlik Ayarları > Tehditler ve İstisnalar

**Güvenlik Ayarları** (Security Settings) menüsünden **Tehditler ve İstisnalar** (Threats and Exclusions) kısmına gidin.

### 3. İstisnaları Yönet

**İstisnaları Yönet** (Manage Exclusions) seçeneğine tıklayın.

### 4. Klasörü Ekle

Aşağıdaki klasörü **tüm alt klasörleriyle birlikte** ekleyin:

```
C:\Users\Recep\Desktop\redzeptech-labs\
```

> **Not:** Projeyi farklı bir konuma taşıdıysanız, o konumun tam yolunu kullanın (örn. `D:\Labs\redzeptech-labs\`).

### 5. Nesne Seçimi

**Nesne** (Object) olarak **Tüm bileşenler** (All components) seçeneğini işaretleyin.

---

## 2. Kaspersky Gelişmiş İstisna (Kritik Adım)

Sadece klasörü eklemek yetmeyebilir. Python scriptlerinin laboratuvar klasöründe yaptığı işlemleri Kaspersky'nin görmezden gelmesi için **Güvenilir Uygulamalar** ayarını yapın:

### Adımlar

1. **Kaspersky Ayarlar** > **Güvenlik Ayarları** > **İstisnalar**
2. **Güvenilir Uygulamalar** (Trusted Applications) sekmesine gidin — bu, normal "İstisnalar"dan farklıdır
3. **python.exe** dosyasını ekleyin (kullandığınız Python sürümünün tam yolu)
   - Örnek: `C:\Users\Recep\AppData\Local\Programs\Python\Python312\python.exe`
   - Yolu bulmak için: `where python` veya `python -c "import sys; print(sys.executable)"`
4. Şu kutucukları işaretleyin:
   - **Açılan dosyaları tarama** (Do not scan opened files)
   - **Uygulama etkinliğini izleme** (Do not monitor application activity)

> **Not:** Bu ayar, Python scriptlerinin laboratuvar klasöründe yaptığı işlemleri Kaspersky'nin görmezden gelmesini sağlar.

---

## Sonuç

Bu ayarlarla (hem klasör istisnası hem Güvenilir Uygulamalar):

- `generate_eicar.py` çalıştığında Kaspersky müdahale etmez
- EICAR test dosyası (`evidence/eicar_test.txt`) oluşturulabilir
- Vault ve statik analiz araçları engellenmeden çalışır

---

## Windows Defender İçin

Windows Defender kullanıyorsanız:

1. **Windows Güvenliği** > **Virüs ve tehdit koruması** > **Ayarlar**
2. **Dışlamalar** > **Dışlama ekle veya kaldır**
3. **Klasör** seçin ve `redzeptech-labs` proje dizinini ekleyin
