*Diğer dillerde okuyun: [English](README.md), [Türkçe](README_tr.md).*

# Macedit Keycloak SMS Authenticator

**MACEDIT Kimlik Doğrulama** için geliştirilmiş Keycloak kimlik doğrulama eklentileridir. SMS tabanlı iki faktörlü kimlik doğrulama (2FA) ve özelleştirilmiş giriş akışları sağlar.

## İçindekiler

- [Özellikler](#özellikler)
- [Yapı](#yapı)
- [Ön Koşullar](#ön-koşullar)
- [Build Alma](#build-alma)
- [Keycloak'a Ekleme](#keycloaka-ekleme)
- [Yapılandırma](#yapılandırma)
- [SMS Gateway Desteği](#sms-gateway-desteği)
- [Direct Grant (REST API) Akışı](#direct-grant-rest-api-akışı)
- [Önbellek (Cache) OTP Depolama](#önbellek-cache-otp-depolama)
- [SMS Kotası ve Brute-Force Koruması](#sms-kotası-ve-brute-force-koruması)
- [İç Ağ Bypass (Regex)](#iç-ağ-bypass-regex)
- [Geliştirme](#geliştirme)
- [Sorun Giderme](#sorun-giderme)

---

## Özellikler

### 1. SMS 2FA Authenticator (`sms-authenticator`)
- Kullanıcı adı + şifre girişinden sonra SMS ile OTP doğrulama
- Dinamik kullanıcı telefon numarası özelliği (`User Mobile Number Attribute` ayarı)
- Özelleştirilebilir kod uzunluğu ve süre sonu (TTL)
- SMS Kotası Koruması (Aynı kullanıcı/IP için SMS tekrar kullanımı)
- Kaba Kuvvet (Brute-Force) koruması (3 yanlış denemede şifre iptali)
- Özelleştirilebilir SMS mesaj şablonu
- Simülasyon modu (test ortamları için - Event detaylarına OTP şifresi yazar)
- İç ağ IP bypass desteği (Regex kuralları ile)

### 2. SMS Direct Grant Authenticator (`sms-direct-grant-authenticator`)
- REST API / Direct Grant akışları için SMS OTP
- Keycloak'ın dahili önbelleği (Infinispan) ile OTP depolama (Harici veritabanı veya Redis gerektirmez)
- Browser akışıyla tamamen aynı SMS Kota, Brute-Force koruması ve Bypass desteği
- OAuth2 hata formatında yanıt döner (`otp_required`)
- `otp` parametresi ile token isteğini doğrulama

---

## Yapı

```
sms-authenticator/
├── src/main/java/macedit/keycloak/authenticator/
│   ├── SmsAuthenticator.java              # Ana SMS authenticator
│   ├── SmsAuthenticatorFactory.java       # Factory sınıfı
│   ├── SmsConstants.java                  # Sabitler
│   ├── gateway/
│   │   ├── SmsService.java                # SMS servis arayüzü
│   │   ├── SmsServiceFactory.java         # SMS servis factory
│   │   ├── TSmsService.java              # XML tabanlı SMS gateway
│   │   └── TRestSmsService.java           # REST/JSON tabanlı SMS gateway
│   └── directgrant/
│       ├── SmsDirectGrantAuthenticator.java
│       ├── SmsDirectGrantAuthenticatorFactory.java
│       ├── SmsDirectGrantConstants.java
│       ├── cache/
│       │   ├── OtpStore.java              # OTP depolama arayüzü
│       │   └── CacheOtpStore.java         # Keycloak SingleUseObjectProvider (Infinispan) implementasyonu
│       └── util/
│           └── IpBypassUtil.java          # Regex tabanlı IP bypass yardımcı sınıfı
├── src/main/resources/theme-resources/
│   └── templates/login-sms.ftl           # SMS giriş şablonu
├── pom.xml
└── README.md
```

---

## Ön Koşullar

- **Java:** 17 veya üzeri
- **Maven:** 3.6+ (veya projedeki `mvnw` wrapper kullanılabilir)
- **Keycloak:** 24.0+ (test edilen: 26.7.0)
- **Docker:** Container ortamı için (opsiyonel)

---

## Build Alma

### SMS Authenticator

```bash
# Proje kök dizininde
mvn clean package -DskipTests

# Oluşan JAR dosyası:
# target/keycloak-2fa-sms-authenticator-1.0.0.jar
```

---

## Keycloak'a Ekleme

### Yöntem 1: Volume Mount (Önerilen - Development)

Container oluştururken JAR dosyalarını volume olarak mount edin:

```bash
docker run -d \
  --name keycloak-test \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "$(pwd)/target/keycloak-2fa-sms-authenticator-1.0.0.jar:/opt/keycloak/providers/keycloak-2fa-sms-authenticator-1.0.0.jar" \
  keycloak/keycloak:latest start-dev
```

---

## Yapılandırma

### Keycloak Admin Console Ayarları

1. **Authentication > Flows** bölümüne gidin
2. **Browser** akışını kopyalayın (ör: "Browser with SMS")
3. **Add executor** > **SMS Authentication** seçin
4. **Requirement** bölümünden **Required** veya **Alternative** seçin
5. **Gear** (dişli) ikonuna tıklayarak yapılandırın

### SMS Authenticator Ayarları

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `User Mobile Number Attribute` | Telefon numarasının çekileceği kullanıcı attribute'u | `mobile_number` |
| `length` | OTP kod uzunluğu | `6` |
| `ttl` | Kod geçerlilik süresi (saniye) | `300` |
| `SMS Reuse Strategy` | SMS Kotası: Tekrar Kullanım Stratejisi (none, user, ip, both) | `user` |
| `Use REST API` | REST API kullan (JSON) | `true` |
| `smsApiUrl` | SMS API endpoint URL | `https://api.macedit.dev/sms` |
| `smsApiUsername` | API kullanıcı adı | - |
| `smsApiPassword` | API şifresi | - |
| `SenderId` | SMS gönderen adı | `MACEDIT` |
| `App Name (REST)` | REST API için uygulama adı | `{realm}/{client}` |
| `SMS Message Template` | SMS mesaj şablonu | `Doğrulama kodunuz: %1$s. Kod %2$d dakika boyunca geçerlidir.` |
| `API Body Template` | Custom JSON istek gövdesi. (Opsiyonel) | `{"msgheader":"{senderId}","msg":"{message}","no":"{phone}","appname":"{appName}"}` |
| `Bypass Internal Network` | İç ağ bypass aktif mi? | `true` |
| `Internal IP (Regex)` | Bypass edilecek IP'ler için Regex kuralı | `^10\.243\..*` |
| `Simulation mode` | Simülasyon modu (SMS göndermez, log ve event'e yazar) | `true` |

### Mesaj Şablonu Değişkenleri

- `%1$s` → OTP kodu
- `%2$d` → Kalan dakika

Örnek: `"MACEDIT Doğrulama kodunuz: %1$s. %2$d dakika geçerlidir."`

---

## SMS Gateway Desteği

### XML API 

`Use REST API = false` iken XML formatında istek gönderilir:

```xml
<?xml version='1.0' encoding='iso-8859-9'?>
<mainbody>
  <header/>
  <body>
    <msg><![CDATA[Doğrulama kodunuz: 123456]]></msg>
    <no>5XXXXXXXXX</no>
  </body>
</mainbody>
```

### REST API (JSON) - Varsayılan

`Use REST API = true` iken JSON formatında istek gönderilir:

```json
{
  "msgheader": "MACEDIT",
  "msg": "Doğrulama kodunuz: 123456",
  "no": "5XXXXXXXXX",
  "appname": "myapp/master/security-admin-console"
}
```

### Telefon Numarası Temizleme

Numaralar otomatik olarak temizlenir:
- `+90 5XX XXX XX XX` → `5XXXXXXXXX`
- `+9 5XXXXXXXXX` → `5XXXXXXXXX`
- `90 5XXXXXXXXX` → `5XXXXXXXXX`
- Boşluklar kaldırılır

---

## Direct Grant (REST API) Akışı

### Adım 1: OTP İsteği

```bash
curl -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=your-client" \
  -d "username=user1" \
  -d "password=pass123"
```

** Yanıt (OTP gönderildi, hata olarak döner):**

```json
{
  "error": "invalid_grant",
  "error_description": "otp_required"
}
```

> Bu beklenen bir davranıştır. İlk istekte OTP üretilir ve SMS ile gönderilir.

### Adım 2: OTP Doğrulama

```bash
curl -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=your-client" \
  -d "username=user1" \
  -d "password=pass123" \
  -d "otp=123456"
```

**Başarılı Yanıt:**

```json
{
  "access_token": "...",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "token_type": "Bearer",
  ...
}
```

---

## Önbellek (Cache) OTP Depolama

Direct Grant ve Browser akışlarının tümünde OTP'ler Keycloak'ın dahili Infinispan önbelleğinde (`SingleUseObjectProvider`) saklanır. Harici bir veritabanına veya Redis'e ihtiyaç yoktur. Cluster ortamlarında otomatik olarak senkronize olur.

### Key Formatı

```
smsotp:{realm}:{clientId}:{username}
```
*(Eğer IP tabanlı SMS Tekrar stratejisi kullanılıyorsa anahtarın sonuna IP adresi de eklenir)*

---

## SMS Kotası ve Brute-Force Koruması

**1. Kaba Kuvvet (Brute-Force) Koruması:** Kullanıcı 3 defa hatalı SMS şifresi girerse, OTP kodu sunucu tarafından anında iptal edilir ve kullanıcıdan yeni bir SMS talep etmesi istenir. Deneme yanılma ile şifre kırılamaz.

**2. SMS Tekrar Stratejisi (Rate Limiting):** Kötü niyetli kişilerin arka arkaya SMS talebi atarak kurumun SMS kotasını tüketmesini engellemek için, Keycloak Admin UI üzerinden **SMS Reuse Strategy** ayarını kullanabilirsiniz:
- `none`: Her defasında yeni SMS gönderilir.
- `user`: Aynı kullanıcı SMS geçerlilik süresi (TTL) dolana kadar istek yaparsa, yeni SMS gönderilmez, eski şifrenin girilmesi beklenir. (Önerilen/Varsayılan)
- `ip`: Aynı IP adresinden gelen isteklerde eski şifrenin girilmesi beklenir. *(Keycloak sunucusunun proxy=edge ayarı ile X-Forwarded-For okuyabildiğinden emin olun)*
- `both`: Hem kullanıcı hem IP eşleştiğinde koruma devreye girer.

---

## İç Ağ Bypass (Regex)

Özellikle development/test ortamlarında veya kurum içi güvenli cihazlardan SMS göndermeden giriş yapabilmek için iç IP adreslerini Regex kuralları ile bypass edebilirsiniz.

### Nasıl Çalışır

1. `Bypass Internal Network = true` olarak ayarlayın
2. `Internal IP (Regex)` parametresine Regex kuralları girin (virgülle ayırarak çoklu kural girebilirsiniz).
3. İstemci IP adresi kurallardan biriyle tam olarak eşleşiyorsa OTP doğrulaması atlanır.

### Örnekler

```
^10\.243\..*                        # 10.243. ile başlayan herhangi bir IP
^192\.168\.1\.50$                   # Yalnızca tam olarak 192.168.1.50 IP adresi
^172\.(16|17)\..*, ^127\.0\.0\.1$   # Virgülle ayrılmış çoklu kurallar
```

---

## Simülasyon Modu

Gerçek telefonlara SMS gitmesini istemediğiniz development ve test ortamları için `Simulation mode` seçeneğini aktif edebilirsiniz. 

Simülasyon modu açıkken:
- SMS Gateway API **tetiklenmez**.
- SMS içeriği ve doğrulama kodu (OTP) Keycloak **server loglarına** uyarı (WARN) olarak yazdırılır.
- Aynı zamanda Keycloak'taki Admin UI **Events (Olaylar)** sayfasında, kullanıcının eyleminin (CUSTOM_REQUIRED_ACTION) ayrıntılarında `code: 123456` bilgisi bulunur.

> **Uyarı:** Canlı (Production) ortamlarda şifrelerin loglanmaması ve gerçek SMS gönderilmesi için Simülasyon modunun kesinlikle **kapalı (false)** olması gerekir.

---

## Geliştirme

### Ortam Kurulumu

```bash
# Java 17+ kurulu olmalı
java -version

# Maven kurulu olmalı (veya mvnw wrapper kullanın)
mvn -version

# Keycloak kaynak kodunu indirin (opsiyonel, referans için)
git clone https://github.com/keycloak/keycloak.git
```

### Proje Yapısı

- `SmsAuthenticator` → Browser akışları için ana authenticator
- `SmsDirectGrantAuthenticator` → REST API akışları için authenticator
- `SmsServiceFactory` → SMS gateway seçimi (XML/REST/Simülasyon)
- `CacheOtpStore` → Keycloak Infinispan tabanlı ortak OTP depolama ve kota sayacı
- `IpBypassUtil` → Regex tabanlı IP güvenlik kalkanı

---

## Sorun Giderme

### Plugin Yüklenmedi

**Sorun:** Console'da SMS authenticator görünmüyor

**Çözüm:**
1. Container loglarını kontrol edin: `docker logs keycloak-test`
2. JAR dosyasının `/opt/keycloak/providers/` dizininde olduğundan emin olun
3. Container'ı yeniden başlatın: `docker restart keycloak-test`

### SMS Gönderilmiyor

**Sorun:** Kod üretiliyor ama SMS gelmiyor

**Çözüm:**
1. `Simulation mode = true` mi? Loglara bakın. Doğrulama kodunu loglarda görüyorsanız, SMS Gateway çağrılmaz. Canlı kullanım için kapatın.
2. `smsApiUrl` doğru mu?
3. `smsApiUsername` ve `smsApiPassword` doğru mu?
4. API yanıt kodunu kontrol edin (200 olmalı)

### Direct Grant Hatası

**Sorun:** `otp_store_failed` hatası

**Çözüm:**
1. Keycloak Infinispan cluster ayarlarının düzgün çalıştığını kontrol edin.
2. Sunucu bellek kapasitesinin dolmadığından emin olun.

---

## Log Örnekleri

```
# Başarılı SMS gönderimi
INFO  [macedit.keycloak.authenticator.gateway.TRestSmsService] REST SMS sent to 5XXXXXXXXX | Response: 200 | Body: ...

# Internal IP bypass
WARN  [macedit.keycloak.authenticator.SmsAuthenticator] Logged With Internal IP: 192.168.1.100

# Simülasyon modu
WARN  ***** SIMULATION MODE ***** 
Would send SMS to 5XXXXXXXXX with text: Doğrulama kodunuz: 123456. Kod 5 dakika boyunca geçerlidir.
Code: 123456

# OTP Kaba Kuvvet Koruması
WARN  [macedit.keycloak.authenticator.SmsAuthenticator] Max OTP attempts reached | Key: user1
```
