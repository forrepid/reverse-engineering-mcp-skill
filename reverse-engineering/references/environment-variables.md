# Ortam değişkenleri ve kullanıcı kurulumu

Araştırma tarihi: 2026-07-14. Bu belge portable
`reverse-engineering-companion` stdio sunucusunun ortam sözleşmesini açıklar.
Canlı `idalib-mcp`, GhidraMCP veya harici detector'ların kendi değişkenleri bu
sözleşmenin parçası değildir.

## İçindekiler

1. Zorunlu değişken var mı?
2. Desteklenen değişkenler
3. Broker bağlantı ayarları
4. Önerilen kurulum
5. PowerShell ile doğrudan kullanım
6. İstemci config biçimleri
7. Güvenlik kuralları
8. Sorun giderme

## Zorunlu değişken var mı?

Hayır. Companion yerel, salt-okunur/planlama sunucusudur; API anahtarı, token,
IDA lisans anahtarı veya uzak servis credential'ı istemez. Değişken verilmezse
güvenli varsayılanlarla başlar. Config renderer bu varsayılanları `env` alanında
açıkça gösterir; böylece kullanıcı etkin sınırları görebilir.

Proje-owned ayar olarak yalnız aşağıdaki `RE_MCP_*` isimleri okunur. Config
üretiminde bilinmeyen bir isim, yanlış sayı, desteklenmeyen mod veya var olmayan
allowed root fail-closed hata üretir. Normal process environment'taki diğer
değişkenler yok sayılır; MCP çıktısında listelenmez.

## Desteklenen değişkenler

| Değişken | Varsayılan | Kural | İşlev |
|---|---:|---|---|
| `RE_MCP_MODE` | `read_only` | Yalnız `read_only` | Apply/debug/eval yüzeyini kapalı tutar |
| `RE_MCP_LOG_LEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | stderr diagnostic düzeyi; stdout yalnız MCP protokolüdür |
| `RE_MCP_MAX_FILE_BYTES` | `536870912` | 1 byte–4 GiB | Companion'ın kabul edeceği en büyük artifact |
| `RE_MCP_MAX_REGION_BYTES` | `1048576` | 1 byte–16 MiB | Selection ve tek-byte XOR için üst sınır |
| `RE_MCP_MAX_SCAN_BYTES` | `67108864` | 256 byte–512 MiB | Entropy scan ve dump planı için üst sınır |
| `RE_MCP_ALLOWED_ROOTS` | boş | Var olan dizinlerin path-list'i | Yetkili sample dizinlerini allowlist eder |
| `RE_MCP_PROVIDER_CONFIG` | boş | Var olan, en çok 64 KiB JSON dosyası | Sağlayıcı executable/rule override kayıtlarını seçer |
| `RE_MCP_PROVIDER_TIMEOUT_SECONDS` | `120` | 1–900 saniye | Harici statik sağlayıcı zaman aşımı |
| `RE_MCP_MAX_PROVIDER_OUTPUT_BYTES` | `4194304` | 1 KiB–64 MiB | Her stdout/stderr kanalı için yakalama sınırı |

`RE_MCP_MAX_REGION_BYTES` ve `RE_MCP_MAX_SCAN_BYTES`,
`RE_MCP_MAX_FILE_BYTES` değerinden büyük olamaz.

`RE_MCP_ALLOWED_ROOTS` boşsa companion, kullanıcı hesabının zaten erişebildiği
dosyalara ek bir root kısıtı koymaz. Kurumsal veya malware-lab kullanımında bu
alanın ayarlanması önerilir. Windows birden çok kökü `;`, macOS/Linux `:` ile
ayırır:

~~~text
C:\Samples;D:\Authorized-Lab
/srv/samples:/opt/authorized-lab
~~~

Symlink ve `..` kaçışını azaltmak için dosya ve root yolları resolve edilir;
sample, resolved root'lardan birinin altında değilse çağrı reddedilir.

## Broker bağlantı ayarları

İsteğe bağlı runtime broker ayarları `.env.example` içinde listelenir ve
readiness çıktısında ayrıca raporlanır. Bunlar `RE_MCP_*` read-only MCP
environment allowlist'inden ayrıdır:

| Değişken | Örnek/değer | İşlev |
|---|---|---|
| `RE_BROKER_PROVIDER` | `none`, `mock`, `cape`, `drakvuf`, `vmray`, `internal` | Broker türünü seçer; varsayılan kapalıdır; `mock` yalnız test içindir |
| `RE_BROKER_BASE_URL` | `http://127.0.0.1:8000/apiv2` | Broker API adresi; varsayılan yalnız loopback kabul eder |
| `RE_BROKER_ID` | `lab-broker-01` | Operator tarafından tanınan broker kimliği |
| `RE_BROKER_TOKEN` | boş | İsteğe bağlı API token; yalnız process environment/secret manager |
| `RE_BROKER_PUBLIC_KEY` | 64 hex karakter | Ed25519 raw public key'in SHA-256 pin'i |
| `RE_BROKER_ALLOW_REMOTE_HTTPS` | `false` | `true` ise HTTPS remote endpoint yapılandırmasına izin verir |

Remote HTTP, URL içine credential/query eklemek ve public-key pin'i olmadan
broker seçmek reddedilir. `readiness` health probe yalnız broker base URL'ine
GET gönderir; sample/task submit etmez. Şimdiki readiness sonucu yapılandırma ve
health erişimini gösterebilir ama `submission_enabled=false` kalır: canlı trace,
dump ve imzalı attestation üreten broker worker adapter'ı ayrı geliştirme ve
kurulum adımıdır. `env-check` ile `client-configs`, MCP'nin `RE_MCP_*`
sözleşmesine dair olduğundan broker girdilerini `.env` dosyasında doğrular,
ancak hiçbir `RE_BROKER_*` değerini (özellikle token'ı) client config'e yaymaz.
Broker credential'ı uygulamaya verilecekse broker'ı başlatan yerel process'e
secret manager'dan enjekte edin; Codex/Claude gibi MCP client config'lerine
token'ı kopyalamayın. `env-check` token'ı yazdırmadan doğrular.

### İzole mock bağlantı testi

Bu sahte backend yalnız `GET /` ve `GET /health` yanıtlar; POST/PUT taleplerini
405 ile reddeder, örnek çalıştırmaz, capture veya imza üretmez. Terminal 1:

~~~powershell
python -m re_core.mock_broker --port 8765
~~~

Terminal 2 (yalnız o terminal oturumu için):

~~~powershell
$env:RE_BROKER_PROVIDER = "mock"
$env:RE_BROKER_BASE_URL = "http://127.0.0.1:8765"
$env:RE_BROKER_ID = "mock-broker"
$env:RE_BROKER_TOKEN = ""
$env:RE_BROKER_PUBLIC_KEY = ""
python scripts\re_cli.py doctor
~~~

Rapor `status=test_only`, `continuous_capture=false`, `submission_enabled=false`
olarak kalmalıdır. Bu test URL/ID'si gerçek CAPE kimliği değildir ve runtime
OEP üretmez.

## Önerilen kurulum

Skill dizininden çalıştırın:

~~~powershell
Copy-Item .env.example .env
notepad .env
python scripts\re_cli.py env-check --env-file .env
~~~

Ardından sekiz istemci için config üretin:

~~~powershell
python scripts\re_cli.py client-configs `
  --output-dir artifacts\client-configs `
  --python "C:\Path\To\Python\python.exe" `
  --env-file .env
~~~

Tek bir değeri dosyayı değiştirmeden override etmek için `--env` kullanın.
Tekrarlanan `--env` değerleri `.env` dosyasından sonra uygulanır:

~~~powershell
python scripts\re_cli.py client-configs `
  --output-dir artifacts\client-configs `
  --env-file .env `
  --env RE_MCP_LOG_LEVEL=INFO `
  --force
~~~

Renderer `.env` dosyasını config'e referans olarak bırakmaz; doğrulanmış dokuz
değeri her companion server entry'sindeki `env` alanına yazar. Manifest aynı
etkin değerleri `companion_environment` altında kaydeder. `idalib-mcp` entry'sine
bu companion değişkenleri eklenmez.

`.env` otomatik yüklenmez. Bu karar, repository içine bırakılan bir dosyanın
fark edilmeden process environment'ına girmesini önler. `.env` Git tarafından
ignore edilir; yalnız `.env.example` paylaşılır.

## PowerShell ile doğrudan kullanım

Yalnız geçerli terminal oturumu için:

~~~powershell
$env:RE_MCP_MODE = "read_only"
$env:RE_MCP_LOG_LEVEL = "INFO"
$env:RE_MCP_ALLOWED_ROOTS = "C:\Samples;D:\Authorized-Lab"
python scripts\re_cli.py env-show
python scripts\re_mcp_server.py --check
python scripts\re_mcp_server.py
~~~

`env-show` mevcut process environment ile varsayılanların birleşimini gösterir.
`env-check` ise yalnız verilen `.env`/`--env` değerlerini doğrular. Normal MCP
kullanımında son komutu kullanıcı elle çalıştırmaz; istemci stdio process'ini
config'teki `command`, `args` ve `env` ile başlatır.

Windows kullanıcı düzeyinde kalıcı değişken gerekirse:

~~~powershell
[Environment]::SetEnvironmentVariable(
  "RE_MCP_ALLOWED_ROOTS",
  "C:\Samples;D:\Authorized-Lab",
  "User"
)
~~~

GUI uygulamaları mevcut shell'in sonradan ayarlanan değişkenlerini görmeyebilir.
Bu nedenle renderer'ın açık `env` alanı, global OS variable'a göre daha
deterministiktir. Kalıcı değişiklikten sonra istemciyi yeniden başlatın.

## İstemci config biçimleri

- Codex: `[mcp_servers.reverse-engineering-companion.env]` TOML tablosu.
  Codex ayrıca host environment'tan isim forward etmek için `env_vars` destekler.
- Claude Code: server içindeki JSON `env`; `${VAR}` ve `${VAR:-default}`
  expansion desteklenir.
- Qwen Code: server içindeki JSON `env`; `$VAR` ve `${VAR}` referansı desteklenir.
- VS Code: server içindeki `env`; ayrıca `envFile` ve secret'lar için
  `${input:...}`/password input desteği vardır.
- Visual Studio: stdio server entry'sinde opsiyonel environment değerleri.
- Zed: `context_servers.<name>.env`.
- Antigravity: `mcpServers.<name>.env`.
- Kimi: `mcpServers.<name>.env`.

Bu proje credential istemediği için renderer secret placeholder üretmez. İleride
uzak bir provider eklenirse token'ı `.env.example`, manifest veya source control
config'ine yazmayın; istemcinin secure input, OAuth, keychain veya environment
forwarding özelliğini kullanın.

Birincil şema kaynakları:

- [Codex MCP](https://developers.openai.com/codex/mcp/)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Qwen Code MCP](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/)
- [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [Visual Studio MCP](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio)
- [Zed MCP](https://zed.dev/docs/ai/mcp)
- [Antigravity MCP](https://antigravity.google/docs/mcp)
- [Kimi MCP](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/mcp.html)

## Güvenlik kuralları

1. `.env` dosyasına API key veya lisans bilgisi koymayın; companion bunları
   kullanmaz.
2. Project MCP config'inin yerel komut çalıştırdığını unutmayın; repository'yi
   ve absolute yolları trust vermeden önce inceleyin.
3. `RE_MCP_ALLOWED_ROOTS` içine bütün disk kökünü eklemeyin; yalnız yetkili
   sample/lab dizinlerini seçin.
4. `read_only` dışında mod vermek sunucuyu açmaz; apply işlemleri ayrı CLI plan,
   hash ve kullanıcı onayıyla yürür.
5. Generated config'i paylaşmadan önce kullanıcı adı ve absolute path'leri
   inceleyin.

## Sorun giderme

Geçerli sözleşmeyi görüntüleyin:

~~~powershell
python scripts\re_cli.py env-show
~~~

Bir env dosyasını doğrulayın:

~~~powershell
python scripts\re_cli.py env-check --env-file .env
~~~

MCP SDK ve runtime ayarını kontrol edin:

~~~powershell
python scripts\re_mcp_server.py --check
~~~

Bağlandıktan sonra MCP `runtime_environment` aracını çağırın. Araç yalnız
allowlist edilmiş dokuz değişkeni, etkin sınırları ve source bilgisini döndürür.

Yaygın hatalar:

- `unknown companion environment variable`: `.env` yalnız `RE_MCP_*`
  sözleşmesindeki dokuz ismi içerebilir.
- `RE_MCP_PROVIDER_CONFIG is not a file`: örnek registry dosyasını kopyalayıp
  gerçek executable/rule yollarını yazın veya değişkeni boş bırakın.
- `entry is not a directory`: allowed-root dizinini önce oluşturun veya yolu
  düzeltin.
- `file is outside RE_MCP_ALLOWED_ROOTS`: sample'ı yetkili root altında açın ya
  da allowlist'i bilinçli biçimde güncelleyin.
- `region/scan length ...`: seçimi küçültün; limiti yükseltmeden önce bellek ve
  çıktı büyüklüğünü değerlendirin.
- İstemci env'i görmüyor: generated config'teki ilgili server `env` alanını ve
  GUI uygulamasının yeniden başlatıldığını kontrol edin.
