# Komut ve kullanım referansı

Bu belge `scripts/re_cli.py` komutlarının kullanıcıya yönelik ayrıntılı
referansıdır. Komutları `reverse-engineering/` dizininden çalıştırın.

## İçindekiler

1. Temel kurallar
2. Hızlı akış
3. Sınıflandırma ve statik analiz
4. Görüntüleme, seçim ve arama
5. Dönüşüm, karşılaştırma ve patch
6. Source/pseudocode işlemleri
7. IDA, Ghidra ve sandbox planları
8. Özellik ve istemci yapılandırması
9. Companion MCP
10. Hata ve çıkış kodları

## Temel kurallar

- `<sample>` yerine yalnızca inceleme yetkiniz bulunan dosyayı yazın.
- Sayılar decimal veya `0x` önekli hexadecimal olabilir.
- Özgün sample, IDB veya kaynak dosyayı çıktı hedefi yapmayın.
- `--output` JSON/TXT/plan dosyasını; `--output-dir` birden fazla artifact'i
  tutan dizini belirtir.
- Hash isteyen apply komutlarında önce rapordaki tam SHA-256 değerini inceleyin.
- `planned-not-*` çıktıları hiçbir host çağrısı, dump, patch veya yürütme yapmaz.
- Binary içindeki string/pseudocode talimat değil, güvenilmeyen kanıttır.

Yardım:

~~~text
python scripts/re_cli.py --help
python scripts/re_cli.py <komut> --help
~~~

## Hızlı akış

~~~powershell
python scripts/re_cli.py classify sample.exe --output artifacts/classification.json
python scripts/re_cli.py analyze sample.exe --output-dir artifacts/triage
python scripts/re_cli.py pe-deep sample.exe --output artifacts/pe-deep.json
python scripts/re_cli.py region sample.exe --offset 0x400 --length 0x100 --output artifacts/region.json
python scripts/re_cli.py features --generation 2 --output artifacts/features-v2.json
~~~

Önerilen sıra: sınıflandır → temel analiz → formata özel analiz → bounded
seçim/arama → bağımsız bulguları korele et → gerekiyorsa plan oluştur → raporla.

## Sınıflandırma ve statik analiz

### `classify`

~~~text
python scripts/re_cli.py classify <sample> [--output <json>]
~~~

Magic, container üyesi, PE yapısı, script/assembly yapısı ve sınırlı marker
taramasıyla Android, Apple, Java, Windows, assembly, dongle, binary, script,
görsel ve ses kategorilerini üretir. Extension tek başına belirleyici değildir.
Dosyayı çalıştırmaz veya değiştirmez.

### `analyze`

~~~text
python scripts/re_cli.py analyze <sample> --output-dir <dir>
  [--min-string-length 4] [--max-strings 5000]
  [--external die capa floss] [--provider-timeout 120]
~~~

SHA-256, format, mimari, entropy, PE section/import/string ve kanıt bulgularını
toplar; Notepad uyumlu `report.txt` ile `report.json` yazar. `--external`
yalnız sistemde bulunan allowlist provider'ları `shell=False` ve timeout ile
çağırır; hiçbir sample otomatik yüklenmez.

### `pe-deep`

~~~text
python scripts/re_cli.py pe-deep <sample> [--output <json>]
~~~

PE declared entry point'i RVA/VA/file-offset/section ile eşler; header/section/
certificate/overlay/EOF sınırlarını, PDB/Rich/packer/runtime/dongle marker'larını,
injection API gruplarını, obfuscation gerekçelerini ve yüksek entropy adaylarını
raporlar. Declared entry point'i gerçek OEP veya entropy'yi encryption kanıtı
olarak sunmaz.

### `inventory`

~~~text
python scripts/re_cli.py inventory <sample> [--output <json>]
~~~

Import DLL/sembol ve section tabanlı dependency envanteri üretir. Dynamic load,
runtime resolver veya paket yöneticisi kapsamı olmadığı için SBOM uyumluluğu
iddia etmez.

### `tools`

~~~text
python scripts/re_cli.py tools [--provider-config <registry.json>]
~~~

25 kanonik provider kaydını; executable/module bulunabilirliği, runnable durumu,
rule gereksinimi ve host-discovery gereksinimiyle listeler. Araç çalıştırmaz;
host provider'lar yalnız katalogda oldukları için aktif sayılmaz.

### `provider-run`

~~~text
python scripts/re_cli.py provider-run --provider <id> --sample <path>
  [--rule <reviewed-rule>] [--provider-config <registry.json>]
  [--timeout 120] [--max-output-bytes 4194304] [--output <json>]
~~~

Yalnız allowlist edilmiş, sample yürütmeyen statik sağlayıcıyı `shell=False`
ile çalıştırır. Sürüm, argüman, return code, çıktı hash'i ve truncation kaydı
üretir. YARA-X reviewed local rule ister. Extract/decompile veya output dizini
isteyen sağlayıcılar bu komutla otomatik çalıştırılmaz.

## Görüntüleme, seçim ve arama

### `inspect`

~~~text
python scripts/re_cli.py inspect <sample> [--offset 0x0] [--length 256]
  [--width 16] [--bits]
~~~

En fazla 1 MiB bounded pencerenin hexdump'ını, `--bits` verilirse bit görünümünü
stdout'a yazar. `offset` file offset'tir; RVA/VA değildir.

### `region`

~~~text
python scripts/re_cli.py region <sample> --offset <file-offset> --length <n>
  [--architecture x64] [--base-address 0x401000] [--output <json>]
~~~

En fazla 1 MiB seçim için hash, entropy, hex, byte, string ve opsiyonel Capstone
linear disassembly üretir. `base-address` yalnız gösterilen instruction adresini
belirler; PE RVA dönüşümü yaptığı varsayılmaz.

### `text-selection`

~~~text
python scripts/re_cli.py text-selection <utf8-source>
  --start-line <n> --end-line <n> [--output <json>]
~~~

En fazla 5000 UTF-8 satırdan import/include, fonksiyon adı adayı, URL,
TODO/FIXME ve crypto terimlerini lexical olarak çıkarır. Metni derlemez veya
çalıştırmaz; parser doğruluğu iddia etmez.

### `search`

~~~text
python scripts/re_cli.py search <sample>
  [--hex "48 8B ?? ??"] [--text "https?://"]
  [--ignore-case] [--limit 1000]
~~~

Wildcard byte pattern ve/veya byte-oriented regex arar. En az bir pattern
zorunludur. Sonuçlar file offset'tir ve limit uygulanır.

### `disasm`

~~~text
python scripts/re_cli.py disasm <sample> --architecture <arch>
  [--offset 0] [--length 256] [--base-address <va>]
  [--limit 1000] [--output <json>]
~~~

Opsiyonel Capstone ile x86/x64/ARM/Thumb/ARM64/MIPS linear sweep yapar. Code/data
sınırı veya control flow analizi değildir; bu işler için IDA/Ghidra kullanın.

### `host-selection-plan`

~~~text
python scripts/re_cli.py host-selection-plan --host ida|ghidra
  [--database <ida-session>] [--address 0x401000] [--end 0x401100]
  [--output <json>]
~~~

IDA için `lookup_funcs/get_bytes/disasm/decompile/xrefs/callees`, Ghidra için
current/function/disassembly/decompile/xref isteklerini planlar. İstek göndermez.
IDA adresi verilmiş planlarda explicit database zorunludur.

## Dönüşüm, karşılaştırma ve patch

### `entropy-map`

~~~text
python scripts/re_cli.py entropy-map <sample> [--offset 0] [--length <n>]
  [--window 4096] [--threshold 7.2] [--limit 1000] [--output <json>]
~~~

En fazla 64 MiB seçimde pencere entropy değerlerini tarar. Eşik üzerindeki
sonuçlar compression/encryption/packing adayıdır; kesin sınıflandırma değildir.

### `xor-scan`

~~~text
python scripts/re_cli.py xor-scan <sample> --offset <n> --length <n>
  [--limit 10] [--output <json>]
~~~

En fazla 1 MiB seçim üzerinde tam 256 single-byte XOR anahtarını dener ve
okunabilirlik puanıyla sıralar. Parola, lisans, credential veya çevrimiçi servis
brute-force aracı değildir.

### `transform-region`

~~~text
python scripts/re_cli.py transform-region <sample>
  --offset <n> --length <n> --operation xor|not|identity [--key 0x5A]
  --confirm-sha256 <hash> --output <new-file>
~~~

Seçilen bölgenin XOR/NOT/identity sonucunu yeni bir dosyaya yazar; kaynak dosya
değişmez. XOR için 0..255 key zorunludur. Çıktı tüm sample değil, yalnız seçilen
dönüştürülmüş bölgedir.

### `compare`

~~~text
python scripts/re_cli.py compare <left> <right> --output <json> [--limit 1000]
~~~

Hash, boyut, format/PE yapısı ve bounded byte-difference aralıklarını
karşılaştırır. Semantic function diff için Generation 2 provider/host planını
kullanın.

### `patch-plan`

~~~text
python scripts/re_cli.py patch-plan <sample> --offset <n>
  --expected "75 05" --replace "90 90"
  [--rationale "neden"] --output <plan.json>
~~~

Kaynak hash'ini ve expected byte'ları doğrular; eşit uzunluklu replacement için
digest ile mühürlü plan yazar. Binary'yi değiştirmez.

### `patch-impact`

~~~text
python scripts/re_cli.py patch-impact <sample> <plan.json>
  [--architecture x64] [--disassembly-window 64] [--output <json>]
~~~

Planı yalnız bellekte uygular; projected hash, section/overlay/certificate,
entropy, signature/checksum ve opsiyonel assembly etkisini gösterir. Dosya yazmaz.

### `patch-apply`

~~~text
python scripts/re_cli.py patch-apply <sample> <plan.json>
  --confirm-sha256 <hash> --output <new-binary>
~~~

Plan digest'i, source hash'i ve expected byte'ları yeniden doğrular; yalnız
mevcut olmayan yeni çıktı üretir. In-place patch ve uzunluk değiştirme yasaktır.

## Source/pseudocode işlemleri

### `source-operation-plan`

~~~text
python scripts/re_cli.py source-operation-plan --host ida|ghidra
  --operation view|read|extract|translate|save|modify|write|binary-inject|process-inject
  [--database <session>] [--address <addr>] [--end <addr>]
  [--target-language c|cpp|rust|python|java|csharp|assembly|pseudocode]
  [--output <json>]
~~~

`view/read/extract/translate/save` read-only artifact akışıdır. `modify/write/
binary-inject` snapshot, sealed plan, hash onayı ve yeni çıktı ister.
`process-inject` her zaman `blocked-by-default` döner. Decompiled pseudocode
özgün kaynak veya doğrudan yeniden derlenebilir kod sayılmaz.

### `source-edit-plan`

~~~text
python scripts/re_cli.py source-edit-plan <utf8-source>
  --mode replace|insert_before|insert_after
  --start-line <n> --end-line <n>
  --replacement-file <utf8-text> [--rationale <text>]
  [--target-language <lang>] --output <plan.json>
~~~

Kaynak hash'i, beklenen satırlar, replacement ve digest içeren sealed edit planı
yazar. Insert modlarında tek anchor satır gerekir. Kaynağı değiştirmez.

### `source-edit-apply`

~~~text
python scripts/re_cli.py source-edit-apply <source> <plan.json>
  --confirm-sha256 <hash> --output <new-source>
~~~

Planı ve seçili satırların değişmediğini doğrular, UTF-8 yeni çıktı yazar.
Export edilmiş pseudocode'u düzenlemek binary veya IDB'yi patch etmez.

## IDA, Ghidra ve sandbox planları

### `hosts`

~~~text
python scripts/re_cli.py hosts [--timeout 0.25]
python scripts/re_cli.py hosts --watch [--interval 2] [--duration 60]
~~~

Yalnız loopback IDA/Ghidra endpoint geçişlerini gözler. Açık TCP portunu güvenilir
MCP kimliği saymaz; sonrasında initialize ve capability discovery gerekir.

### `capabilities`

~~~text
python scripts/re_cli.py capabilities --host ida|ghidra
  --endpoint <loopback-url> [--tools <tool> ...] [--resources <uri> ...]
~~~

Canlı keşiften alınmış tool ve resource isimlerini read/annotate/patch/debug
sınıflarına normalize eder. Bilinmeyen yüzeyleri fail-closed listeler;
endpoint'e bağlanmaz.

### `ida-profile`

~~~text
python scripts/re_cli.py ida-profile --ida "C:\Program Files\IDA Professional 9.4\ida.exe"
  [--python <python.exe>] [--no-hashes] [--output <json>]
~~~

IDA sürümü, idalib, IDAPython, activation script, wheel ve MCP plugin durumunu
çalıştırmadan profiller. Varsayılan hash toplama daha yavaştır fakat provenance
için önerilir.

### `idalib-plan`

~~~text
python scripts/re_cli.py idalib-plan --ida <ida.exe>
  [--python <python.exe>] [--mcp-executable <idalib-mcp.exe>]
  [--transport stdio|http] [--host 127.0.0.1] [--port 8745]
  [--max-workers 4] [--no-hashes] [--output <json>]
~~~

Activation ve allowlist edilmiş MCP command array'lerini üretir. IDA, activation
script veya MCP sunucusunu başlatmaz. HTTP yalnız loopback olabilir; stdio tercih
edilir.

### `ida-context-plan`

~~~text
python scripts/re_cli.py ida-context-plan --database <session-id>
  --address <addr> [--byte-count 64] [--output <json>]
~~~

Explicit database için bounded IDA context tool çağrılarını sıralar. MCP isteği
göndermez ve auto-analysis tamamlandı varsayımı yapmaz.

### `ida-deeplink`

~~~text
python scripts/re_cli.py ida-deeplink --database <session-id> --address <addr>
  [--view disassembly|pseudocode|hex|graph] [--output <json>]
~~~

Proje içi `re-idb://` navigasyon kaydı üretir. Ayrı reviewed handler kurulmadan
native IDA URL handler değildir.

### `snapshot-idb`

~~~text
python scripts/re_cli.py snapshot-idb <database.i64> --confirm-saved
  --output-dir <dir> [--label before-change]
~~~

Operatörün IDA'nın database'i kaydettiğini onaylamasını ister; kaynak hash'ini
kontrol edip yeni immutable snapshot ve manifest oluşturur.

### `snapshot-restore-plan`

~~~text
python scripts/re_cli.py snapshot-restore-plan <manifest.json>
  --target <database.i64> [--output <json>]
~~~

Snapshot hash'ini doğrular ve manuel restore adımlarını planlar. Target IDB'yi
otomatik değiştirmez; restore sırasında IDA kapalı olmalıdır.

### `dump-plan`

~~~text
python scripts/re_cli.py dump-plan --host ida|ghidra --kind static|runtime
  --database <session> --address <addr> --length <n> [--output <json>]
~~~

IDA static dump için `get_bytes`, runtime dump için `dbg_read` planlar. Runtime
debug modu, izole target ve açık onay ister. Güncel Ghidra bridge'inde uygun raw
dump aracı yoksa `capability-unavailable` döner.

### `sandbox-plan`

~~~text
python scripts/re_cli.py sandbox-plan <sample> --provider <name>
  [--timeout 300] [--network blocked|simulated|restricted] --output <json>
~~~

Hash, timeout, snapshot ve ağ politikalı dinamik analiz planı yazar; sample'ı
hiçbir zaman çalıştırmaz veya provider'a göndermez.

## Özellik ve istemci yapılandırması

### `features`

~~~text
python scripts/re_cli.py features [--generation 1|2]
  [--category <name>] [--status <status>] [--output <json>]
~~~

Toplam 50 özellik sözleşmesini listeler. Generation 1 ilk 25, Generation 2 yeni
25 öneridir. Status/category filtreleri birlikte uygulanır.

### `feature-plan`

~~~text
python scripts/re_cli.py feature-plan --feature <feature-id>
  --host local|ida|ghidra [--sample <path>] [--database <session>]
  [--address <addr>] [--discovered-tools <tool> ...]
  [--discovered-resources <uri> ...] [--output <json>]
~~~

Tek özellik için local implementation, provider, IDA/Ghidra tool sequence ve
guard listesini planlar; tool çağrısı yapmaz.

### `feature-check`

~~~text
python scripts/re_cli.py feature-check [--output <json>]
~~~

50 feature kimliğini, generation başına 25 kayıt şartını, status/mode
değerlerini, provider kimliklerini ve IDA/Ghidra tool/resource adlarını doğrular.

### `feature-run`

~~~text
python scripts/re_cli.py feature-run --feature <local-feature-id> --sample <path>
  [--second-sample <path>] [--max-scan-bytes 67108864] [--output <json>]
~~~

Allowlist edilmiş yerel bir özelliği bounded ve non-mutating çalıştırır.
Anti-analysis, persistence, protocol, config/embedded carving, archive audit,
signature structure, debug path, dependency, coverage, evidence ve iki dosyalı
diff/regression akışlarını kapsar. Sample çalıştırılmaz; dosya çıkartılmaz.

### `env-show`

~~~text
python scripts/re_cli.py env-show [--output <json>]
~~~

Companion'ın allowlist edilmiş dokuz `RE_MCP_*` değişkenini; tip, varsayılan,
sınır, mevcut process'teki etkin değer ve kaynağıyla gösterir. İşletim
sistemindeki başka environment değerlerini listelemez. Hiçbir secret gerekli
değildir.

### `env-check`

~~~text
python scripts/re_cli.py env-check [--env-file <path>]
  [--env NAME=VALUE ...] [--output <json>]
~~~

UTF-8 `.env` dosyasını ve tekrarlanabilir `--env` override'larını fail-closed
doğrular. Yalnız tanımlı `RE_MCP_*` isimleri kabul edilir; `--env` aynı ismin
env-file değerinden sonra uygulanır. Dosyayı process environment'ına yüklemez ve
client config yazmaz.

### `doctor`

~~~text
python scripts/re_cli.py doctor
  [--ida <ida.exe>] [--idalib-mcp <idalib-mcp.exe>]
  [--ghidra-home <dir>] [--ghidra-bridge <bridge_mcp_ghidra.py>]
  [--ghidra-server http://127.0.0.1:8080/]
  [--output <json>]
~~~

Kilitli Python bağımlılıklarını, feature kataloğunu, 25 provider'ı ve açıkça
verilen IDA/Ghidra yollarını tek readiness raporunda denetler. Program/IDB
açmadan `config_ready` hesaplar. Kurulu GhidraMCP extension JAR'ını da zorunlu
tutar ve yalnız loopback `/health` yanıtı geldiyse `live_plugin_verified`, aktif
Program adı geldiyse `live_program_verified` raporlar; açık port tek başına
canlı host kanıtı değildir.

### `client-profiles`

~~~text
python scripts/re_cli.py client-profiles [--output <json>]
~~~

Codex, Claude Code, Qwen Code, VS Code, Visual Studio, Zed, Antigravity ve Kimi
config formatlarını, output adlarını ve merge hedeflerini gösterir.

### `client-configs`

~~~text
python scripts/re_cli.py client-configs --output-dir <dir>
  [--python <python.exe>] [--companion-script <re_mcp_server.py>]
  [--idalib-mcp <idalib-mcp.exe>] [--clients codex zed kimi]
  [--ghidra-bridge <bridge_mcp_ghidra.py>]
  [--ghidra-server http://127.0.0.1:8080/]
  [--max-workers 4] [--env-file <path>] [--env NAME=VALUE ...]
  [--force]
~~~

Seçilen istemciler için absolute-path MCP config parçaları ve manifest üretir.
Gerçek client ayarlarını değiştirmez. Companion her zaman, idalib yalnız exact
allowlist basename ile verildiğinde eklenir; Ghidra bridge exact basename ve
loopback URL ister. `--force` yalnız renderer output dizinindeki önceden
üretilmiş config'leri değiştirir. Renderer dokuz güvenli
companion değişkenini her client'ın `env` alanına, manifest'e ise
`companion_environment` olarak yazar. `.env` otomatik yüklenmez.

## Companion MCP

~~~text
python scripts/re_mcp_server.py --check
python scripts/re_mcp_server.py
~~~

`--check`, MCP SDK import edilebilirliğini, salt-okunur güvenlik durumunu ve
etkin allowlist edilmiş ortam sözleşmesini JSON
olarak verir ve kalıcı sunucu başlatmaz. İkinci komut stdio sunucusunu başlatır;
normal kullanımda bunu doğrudan terminalden değil MCP client lifecycle'ından
başlatın. Stdio stdout'una debug metni yazmayın; protokol mesajlarına ayrılmıştır.

## Hata ve çıkış kodları

- `0`: işlem başarıyla tamamlandı.
- `2`: kullanıcı girdisi, güvenlik kapısı, parse, provider veya dosya hatası.
- Traceback yerine `error: ...` mesajı beklenir; hata sessizce yutulmaz.
- Kısmi analizlerde başarılı kanıt korunur, eksikler `limitations` alanına yazılır.
