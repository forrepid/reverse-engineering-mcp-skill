# Reverse Engineering Companion — takip hedefleri

Bu belge maincontrat.md içindeki takip hedefinin uygulanabilir kontrol listesidir.
Öncelik sırası güvenlik etkisine göre düzenlenmiştir; tamamlanma kanıtı
`maincontrat.md` içine de işlenmelidir.

## Güvenlik ve kaynak tüketimi

- [x] IDA için upstream `--profile` allowlist, Ghidra için bridge tool
  registration filtresi üzerinden `read_only` profili renderer'a bağlandı;
  `current` varsayılanı korunur ve unknown host tools fail-closed raporlanır.
  Renderer ve filter unit testleri geçti; tam canlı Ghidra host list testi aşağıda
  ayrı E2E maddesinde açık tutulur.
- [x] Kullanıcı onayıyla sınırlı `read_write` host profili: IDA reviewed
  whitelist'i yalnız READ/ANNOTATE sınıflarından kabul eder; Ghidra köprüsü de
  aynı şekilde salt-okunur + anotasyon araçlarını kaydeder. Config üretimi
  `--confirm-read-write` olmadan reddedilir; generated config'lerde istemci
  tool-approval prompt'u korunur. Patch, debugger, dynamic ve arbitrary Python
  araçları dahil edilmez. Unit/negative testler ve pinned patch apply doğrulandı;
  canlı host write E2E'si ayrıca yapılmadı.
- [x] TAR/ZIP denetiminde kaynak dosya, üye, toplam açılmış bayt, ZIP
  central-directory byte/member sayısı, üye-başına oran ve süre limitlerini
  fail-closed uygula. ZIP end record `infolist()` nesneleri oluşturulmadan
  denetlenir; TAR oranı toplam sıkıştırılmış arşiv boyutuna göre yaklaşık
  raporlanır. Negatif oran/member/index/source-limit testleri eklendi.
- [x] Analyzer/deep PE/compare ve feature yollarına ortak scan/file bütçesi
  aktarmak; PE deep tam imaj istediği için 64 MiB working-set üstünü reddeder,
  analyzer partial scan limitasyonunu raporlar, dependency inventory CLI ve
  feature yollarına etkin file/scan limitlerini aktarır ve byte-diff hex
  ayrıntısını 4 KiB ile sınırlar. Streaming hash/diff ve negatif limit testleri
  eklendi.
- [x] Ghidra loopback API loopback-only + zorunlu bearer token; auth tüm
  routes'e bağlandı, `/health` eklendi ve token yoksa plugin başlamıyor.
  HTTP authenticator test returns 401 for absent/wrong tokens and 200 for the
  valid token; pinned patch/build and Maven test pass. Never commit the token.

## Kapsam ve doğrulanabilirlik

- [x] 8 MiB üstünde seek tabanlı header/interior/tail taraması ve kategori
  sınıflandırması var; 9 MiB fixture'da dosya sonundaki dongle işareti bulundu.
- [x] Probe aracı gerçek MCP initialize + tools/resources list sonuçlarından
  capability coverage üretir. IDA `read_only` canlı keşif: 43 tool, 8
  resource, 33 capability'nin 22'si (`0.6667`), unknown tool/resource yok.
- [x] Token'lı Ghidra 12.1.2 CodeBrowser canlı coverage/E2E doğrulandı. Ayrı
  geçici Ghidra dağıtım kopyası ve izole `application.settingsdir` kullanıldı;
  ana kurulum/extension değiştirilmedi. `Hermes-Setup (1).exe` yalnızca Ghidra
  statik analizinden geçirildi, çalıştırılmadı. CodeBrowser'da yalnızca
  `GhidraMCPPlugin` etkinleştirildi ve araç yapılandırması kaydedildi.
  Auth verifier: HTTP eksik/yanlış/doğru token `401/401/200`; MCP initialize,
  list-tools, list-resources ve `ghidra_health`, `list_functions`,
  `get_current_function` başarılı. `read_only`: 16 araç, 0 resource, 13/17
  capability (`0.7647`), 0 unknown tool/resource; health `status=ok`, etkin
  Program doğru, function listing boş değil. Verifier alt sürecine korumalı
  token aktarımı da düzeltildi (kaynağa/loga yazılmaz).
  E2E öncesi yanlışlıkla global `%APPDATA%` ayarını kullanan eski GUI denemesi
  tarihsel negatif kontroldür: 401/401/200 sözleşmesi sağlanmadığı için
  güçlendirilmiş verifier doğru biçimde başarısız oldu; sample mutation/call
  yapılmadı.
- [x] Doctor'a isteğe bağlı salt-okunur IDA/idalib MCP initialize/tools/list
  probe eklemek; probe yapılmadığını `not_checked` diye göstermek. Yerel
  idalib-mcp canlı testinde initialize ve 65 tool keşfi geçti; IDB açılmadı.
- [x] Yerel negatif testler, operator docs, IDA live MCP discovery, pinned
  Ghidra patch apply/build, large-file negative cases, IDA readiness ve
  authenticated live Ghidra CodeBrowser E2E kanıtlandı.

## Açık / tamamlanan durum

Bu takip hedefinin host mutation/read-only güvenlik profilleri, arşiv/bellek
bütçeleri, büyük-dosya sınıflandırması, canlı IDA readiness ve authenticated
Ghidra coverage/E2E maddeleri uygulama ve doğrulama kanıtlarıyla tamamlandı.

## M8 — İzole dinamik analiz: user-mode ve kernel-mode (yeni hedef)

Amaç: IDA/Ghidra statik sonuçlarıyla ilişkilendirilebilen, tekrar üretilebilir,
kanıt/provenance taşıyan ve ana makineden ayrılmış dinamik analiz. Bu bölüm
araştırma ve uygulama sırasıdır; burada listelenen işler henüz uygulanmış
özellikler sayılmaz. Örnek dosya varsayılan olarak host'ta çalıştırılmaz.

### Sıralı geliştirme planı

1. **M8.1 — Tehdit modeli ve yetki sınırı.** VM broker ayrı, dar yetkili
   bileşen olur; MCP çekirdeği host'ta örnek çalıştırmaz, yönetici yetkisi
   istemez ve host güvenlik kontrollerini kapatamaz. Her çalışma için dosya
   SHA-256, kullanıcı yetkilendirmesi, süre/CPU/RAM/disk/çıktı bütçesi ve
   iptal/kill/cleanup sözleşmesi zorunludur. Planlama (`sandbox-plan`) ile
   yürütme farklı yeteneklerdir; `start` açık kullanıcı onayı ister.
2. **M8.2 — Backend sözleşmesi ve kaynak yaşam döngüsü.** Türlenmiş
   `plan/start/status/events/export/stop/destroy` API'si; provider capability
   keşfi, idempotent teardown, zaman aşımı, audit kimliği ve hata durumları.
   Adapter'lar core'dan ayrı çalışır. Başlangıçta sadece dry-run ve sahte
   backend testleri; sağlayıcı adı tek başına güven kanıtı değildir.
3. **M8.3 — Windows user-mode MVP.** Kısa, disposable oturum için Windows
   Sandbox adapter'ı; uzun/tekrar edilebilir oturum için Hyper-V Gen 2 golden
   image + temiz clone/checkpoint. Ağ, clipboard, mikrofon, yazıcı ve vGPU
   kapalı; host paylaşımı yok (gerekirse hash doğrulamalı, tek yönlü,
   salt-okunur staging). Kaynak ve süre limitleri; guest'te düşük yetkili
   analiz hesabı. Sandbox'ın ağ ve clipboard varsayılanlarının açık olabildiği
   için config açıkça üretilip doğrulanmalıdır.
4. **M8.4 — User-mode davranış izleme.** Windows ETW/Sysmon gibi belgelenmiş
   event kaynaklarıyla process/tree, thread, image/DLL load, file, registry,
   service/task, named pipe ve socket/DNS olayları; Linux'ta guest içi audit,
   proc connector/eBPF user-space tüketicileri veya auditd. Her olayda UTC ve
   monotonic timestamp, PID/PPID, image/hash, session/sample id ve kaynak
   sağlayıcı tutulur. Sysmon opsiyonel provider'dır; sensör kurulumu image
   build aşamasında yapılır, örnek çalışırken host'a agent kurulmaz.
5. **M8.5 — Ağ davranışı laboratuvarı.** Varsayılan sıfır egress ve internete/
   yerel ağa route yok. İhtiyaç varsa ayrı sanal switch + DNS sinkhole ve
   protokol simülatörleri; dış ağa çıkış yalnız allowlist, süreli politika ve
   ayrıca onayla. PCAP/akış/DNS/HTTP metadata'sı sınırlandırılmış ve hassas
   veri redaksiyonlu kaydedilir. Ağ kapalıyken davranışın eksik gözlenebileceği
   raporda açıkça işaretlenir.
6. **M8.6 — Windows guest kernel-mode telemetry.** Önce host dışı Hyper-V
   guest içinde ETW kernel provider/WPP ve debugger destekli test lab; process,
   thread, image, I/O ve driver olayları. WDK test imzalı driver sadece
   disposable guest'te, Secure Boot/code-integrity politikasının etkisi
   belgelenerek ve kullanıcı onayıyla denenebilir. Host'a driver yükleme,
   host kernel callback/hook/patch veya korumaları atlatma bu ürünün kapsamı
   dışındadır. Crash dump/bugcheck'i VM başına kotayla toplar.
7. **M8.7 — Linux guest kernel-mode telemetry.** KVM/QEMU disposable guest'te
   önce tracefs/ftrace/tracepoint/perf; event allowlist ve ring-buffer/drop
   sayacı. eBPF ek provider'ı verifier'dan geçen sabit/denetlenmiş programlarla
   sınırlanır; arbitrary BPF/module yükleme yok. Kprobe yalnız tracepoint
   yetmediğinde, kernel build/symbol sürümü pinlenmiş ve allowlist'li lab
   profilinde. Host kernel'e probe/agent eklenmez.
8. **M8.8 — Ortak olay şeması ve korelasyon.** Windows/Linux event'lerini
   canonical process, module, file, registry/config, memory, network ve
   kernel-event şemasına dönüştür; ham kaynak olayını da koru. IDA/Ghidra
   adreslerini yalnız build id, image hash, mimari, load base ve PDB/DWARF
   eşleşmesi kanıtlanırsa bağla; belirsiz adres dönüşümünü tahmin diye işaretle.
   Zaman çizelgesi, process tree, IOC ve statik bulguyla korelasyon üret.
9. **M8.9 — Kanıt paketi ve raporlama.** Manifest'te örnek hash, VM image
   digest, host/hypervisor/guest ve sensor sürümleri, config/network policy,
   başlangıç-bitiş, checkpoint kimliği, event loss, exit/crash ve artefact
   hash'leri bulunur. JSON/CSV/TXT + ETL/EVTX/PCAP gibi ham çıktılar; boyut ve
   saklama kotası, export öncesi gizli veri uyarısı ve tekrar oynatılabilir
   zaman çizelgesi. “Olay yok” sonucunda sensör kapsamı ve kayıp sayaçları
   belirtilir.
10. **M8.10 — MCP ve IDE entegrasyonu.** Tüm IDE/istemciler aynı MCP
   `sandbox_*` araçlarını kullanır: plan, onaylı start, status, stop, events,
   export, destroy. IDE eklentileri yalnız seçili fonksiyondan statik
   bağlam/hash ekler; örneği kendiliğinden başlatmaz. Read-only profile
   yürütme araçlarını listelemez. Argümanlar schema/allowlist doğrulamasından
   geçer; arbitrary shell, host path, VM console veya ağ kuralı çalıştırma
   aracı sunulmaz.
11. **M8.11 — Sertleştirme ve kabul kapıları.** Snapshot'tan temiz başlama,
   ağ egress deny testi, host paylaşımı yokluğu, stop/timeout/crash sonrası
   teardown, kota taşması, event-loss, sensör kapalı/eksik durum, yanlış VM
   kimliği ve broker kesintisi için negatif testler. VM escape garantisi iddia
   edilmez; güncel hypervisor/guest patch seviyesi ve risk istisnası raporlanır.
   Windows Sandbox, Hyper-V, Linux KVM sürüm matrisi; performans/telemetry
   overhead ölçümü ve yetkili temiz örnek corpus'u olmadan “endüstriyel hazır”
   denmez.
12. **M8.12 — Üretimleştirme ve sağlayıcı seçimi.** Önce Windows yerel lab ve
   Linux KVM lab için sınırlı pilot; CAPE/DRAKVUF/VMRay entegrasyonları ayrı
   opsiyonel adapter olarak, lisans/kurulum/gizlilik/ağ modeli ve sağlayıcı
   raporu doğrulandıktan sonra. İmzalı broker/agent, SBOM, güncelleme kanalı,
   audit saklama/erişim politikası, operasyon runbook'u ve disaster cleanup
   testleri tamamlanınca GA adayı.

### Araştırma sonucu ve yöntem seçimi

- **Hızlı Windows triage:** Windows Sandbox tek kullanımlık oturum için
  uygundur; `.wsb` ile ağ/vGPU kapatılabilir, bellek sınırı ve salt-okunur
  klasör tanımlanabilir. Fakat varsayılan ağ ve clipboard açıktır; host klasörü
  eşlemesi risk taşır. Bu nedenle MVP'de paylaşım yok, gerekli örnek transferi
  kontrollü staging'den yapılır.
- **Tekrarlanabilir Windows ve kernel analizi:** Hyper-V disposable Gen 2
  VM'ler, sabit guest image ve checkpoint/clone yaşam döngüsü. Üretim
  checkpoint'i tutarlı backup içindir, RAM state tutmaz; yürütme öncesi temiz
  runtime state gerekiyorsa standard checkpoint/clone semantiği açıkça
  seçilmeli ve yan etkileri test edilmelidir. Nested virtualization yalnız
  konukta hypervisor gerektiren özel testlerde; temel analiz için şart değil.
- **Linux user/kernel analizi:** KVM guest; önce tracepoint/ftrace/perf,
  ardından eBPF verifier'lı sınırlı programlar. Tracepoint'ler yapılandırılmış
  olay toplamak için kprobe'lardan daha kararlı ilk tercih; kprobe sürüm ve
  sembol bağımlılığı taşır. Sensörler guest içinde çalışır, host kernel'e
  dokunulmaz.
- **Olay kaynağı ve kayıt:** Windows ETW user/kernel event altyapısıdır;
  Linux kernel tracepoint ve event tracing sistemleri yapılandırılmış
  telemetry sağlar. Her iki tarafta ham olay saklanır, normalize görünüm
  türetilir ve event loss ayrı metrik olur.
- **Yetki modeli:** statik analiz her zaman varsayılan; sandbox başlatma
  açıkça yetkilendirilmiş, zaman/kaynak limitli bir mutation sayılır. Ağ
  bağlantısı ikinci onay ve dar allowlist gerektirir. Kernel instrumentation
  yalnız disposable guest içinde ve backend capability destekliyorsa açılır.

Araştırma kaynakları: Microsoft [Windows Sandbox yapılandırması](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file), [örnek izolasyon konfigürasyonu](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-sample-configuration), [Hyper-V checkpoint türleri](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/choose-between-standard-or-production-checkpoints-in-hyper-v), [nested virtualization](https://learn.microsoft.com/virtualization/hyper-v-on-windows/user-guide/nested-virtualization), [Windows ETW](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal); Linux kernel [tracepoint'ler](https://docs.kernel.org/trace/tracepoints.html), [event tracing](https://docs.kernel.org/6.5/trace/events.html), [eBPF verifier](https://docs.kernel.org/bpf/verifier.html), [KVM API](https://docs.kernel.org/6.0/virt/kvm/api.html).

## M9 — OEP adayını otomatik bulma ve güvenli runtime doğrulama (yeni hedef)

Amaç: declared entry point'i otomatik başlangıç noktası alıp olası original
entry point (OEP) adaylarını kanıtlarıyla bulmak/göstermek; runtime OEP'yi ise
sadece ayrıca onaylanmış izole trace ve o oturumdan alınan dump ile doğrulamak.
Bu bölüm plan durumundadır; mevcut sistem runtime OEP'yi otomatik doğruluyor
anlamına gelmez. Otomatik olan statik aday taraması/raporlama ve kullanıcı
onayından sonra sandbox içindeki sınırlı izleme orkestrasyonudur; örnek hiçbir
koşulda host'ta otomatik başlatılmaz.

### Sıralı geliştirme planı

1. **M9.1 — Kanıt sözleşmesi ve durumlar.** [~] Statik raporda örnek
   SHA-256, mimari, image base, declared EP ve aday başına status, RVA/VA/file
   offset, section, gerekçe ve confidence kaydediliyor; `candidate` veya
   `reference_not_verified` statüleri var, statik yol `verified` üretemez.
   Runtime trace/dump provenance doğrulayıcısı sonraki aşamada tamamlanacak.
   Nihai durum kümesi `candidate`, `verified`, `inconclusive`, `rejected` olup
   her aday yöntem, ham kanıt referansı ve sınırlama taşımalıdır. Adres eşlemesi
   belirsizse kesin adres yerine aralık/tahmin belirtilir.
2. **M9.2 — Statik PE aday keşfi.** [~] PE başlıkları/bölümleri, declared EP
   map'i, executable section entry hipotezleri, RVA/VA/file-offset, section
   permission/entropy, TLS directory varlığı ve sınırlamalar read-only JSON,
   CLI ve companion MCP (`oep_static_candidates`) üzerinden raporlanıyor.
   Statik/runtime ayrımı, zero-fill ve çakışan section adres eşlemesi için
   negatif testler mevcut; çakışmada file offset fail-closed biçimde silinir.
   TLS callback VA/RVA/file-offset statik ayrıştırması eklendi; yalnızca
   file-backed diziler, bounded 128 callback limiti ve terminatör durumu
   raporlanır. Bu callback'lerin çalıştığı anlamına gelmez. PE32/PE32+
   Load Configuration GuardFlags/Guard CF function-table verisi bounded
   biçimde parse edilir; entry RVA tablo üyeliği metadata sinyali olarak sunulur.
   Import edilmiş bellek koruma/allocation ve dynamic resolver API kategorileri,
   packer marker'ları ve yüksek entropy executable section'lar bağımsız
   korelasyon sinyali olarak listelenir; import call-site/runtime kullanımı veya
   CFG runtime enforcement iddiası yoktur. Negatif malformed size/table limit
   testleri eklendi; gerçek fixture corpus'u ve control-flow doğrulaması açık.
   Nihai tarayıcı EP'nin section/izin/offset
   ilişkisini, TLS callback'lerini, import/API izlerini, control-flow
   geçerliliğini, packed-section/packer göstergelerini ve bounded entropy
   pencerelerini birlikte değerlendirmeli; heuristikleri kanıt/garanti gibi
   sunmamalı.

   Araştırma: Microsoft [PE Format — TLS ve Load Configuration/Guard CF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
   ve [PE metadata — Guard CF function table](https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata).
3. **M9.3 — IDA/Ghidra statik kanıt adaptörleri.** İsteğe bağlı host MCP
   adaptörleri EP çevresi disassembly/decompile, function boundary, xref,
   import ve varsa CFG özelliklerini salt-okunur toplar. Host bulunmadığında
   temel dosya taraması devam eder; eksik yetenek/scope ve başarısız analiz
   görünür raporlanır. Adresler hash, image base ve mimari doğrulanmadan
   dosyalar/host'lar arasında eşleştirilmez.
4. **M9.4 — Aday sıralama ve açıklanabilir rapor.** Birden çok yöntemin
   bağımsız sinyalleri normalize edilip adaylar sıralanır; skor olasılık veya
   garanti diye sunulmaz. TXT/JSON görünümü declared EP ile her adayı,
   VA/RVA/file offset'i, dayanak sinyalleri, çelişkili bulguları, confidence
   ve “statik aday, runtime doğrulanmadı” uyarısını yan yana gösterir.
5. **M9.5 — Onaylı runtime planı.** [~] `sandbox-plan` salt plan üretir; image
   SHA-256, temiz snapshot ID ve bounded CPU/RAM/disk/trace/dump kotası alanları
   eklendi. Image/snapshot yoksa `ready_for_broker_submission=false`; plan
   örneği çalıştırmaz ve broker'a göndermez. Runtime doğrulama isteği önce `sandbox-plan`
   üretir: sample hash'i, disposable VM/image digest'i, snapshot, sıfır-egress
   ağ politikası, zaman/CPU/RAM/disk/dump/event kotası, telemetry sağlayıcısı,
   durdurma/cleanup adımları ve beklenen kanıtlar. Planı görüntülemek örneği
   çalıştırmaz; kullanıcı bu spesifik planı açıkça onaylamadan start çağrısı
   yapılamaz. Read-only profile start yetkisi listelemez.
6. **M9.6 — Sınırlı trace orkestrasyonu.** Onaydan sonra yalnız kayıtlı broker
   disposable guest'te örneği bir kez/süre kotası içinde başlatır; process,
   module/DLL load, memory map/protection, exception ve control-flow olaylarını
   izinli sensörlerden toplar. Executable private memory, image dışı yürütme,
   unpack/import-resolution izleri candidate üretebilir; debugger bypass,
   anti-analysis atlatma, host injection veya keyfi komut arayüzü eklenmez.
7. **M9.7 — Dump alma ve imaj rekonstrüksiyonu.** Dump yalnız ilgili onaylı
   sandbox oturumundan ve kota dahilinde alınır. Dump ve ham trace değişmez
   artefact olarak hash'lenir; kaynak sample'a in-place yazılmaz. Rekonstrüksiyon
   modülü bölüm/izin/RVA/relocation/import tutarlılığı ve mapped-image sınırını
   denetler; düzeltme gerekiyorsa yeni çıktı + mühürlü plan üretir, kaynak
   örneği veya canlı process'i değiştirmez.
8. **M9.8 — Runtime OEP doğrulama kapıları.** [~] `oep-runtime-verify` yalnız
   kanıt import eder: exact user-confirmed plan hash, plan/snapshot/image/network
   policy, operator-pinned broker Ed25519 key + broker ID, sample/trace/dump
   hashes, signed approval, zero event loss, normalized event order, executable
   memory map, reconstructed PE `AddressOfEntryPoint` ve executable section
   eşleşmesini doğrular. Eksik/loss'lu
   kanıt `inconclusive`; imza/hash/plan uyuşmazlığı `rejected`; hiçbir dosya
    çalıştırılmaz. Sentetik fixture tests pass. Sonuçta `oep_display` alanı
    doğrulanmış VA/RVA/file offset'i veya NOT VERIFIED durumunu belirgin sunar;
    statik `oep_result` declared EP'yi yalnız referans olarak gösterir.
    Import/relocation kalite skoru, gerçek broker signing/capture,
   live VM ve clean authorized corpus henüz entegre/doğrulanmış değildir.
   `verified` için trace'in doğru
   sample/session hash'ine ait olması; aday adresin yürütülmüş executable
   imaj bölgesinde bulunması; loader/unpack geçişi sonrası kontrolün anlamlı
   kod akışına ulaşması; dump'ın parse edilip adres/section/import
   kontrollerinden geçmesi ve trace-dump-image eşleşmesinin gösterilmesi
   gerekir. Kısmi telemetry, event loss, çökme, timeout, adres uyuşmazlığı veya
   bozuk dump varsa sonuç `inconclusive` kalır; OEP tahmin edilerek yükseltilmez.
    Broker adapter sözleşmesi: `references/runtime-oep-evidence.md`. Broker şu
    an yapılandırılmış değildir; plan örneği çalıştırmaz/göndermez ve sürekli
    capture başlatmaz. CAPE REST API task submit/status/report ve result archive
    uçları sunar; fakat bizim lossless normalize trace + reconstructed PE + plan
    bound Ed25519 sözleşmesini hazır sağladığı varsayılamaz. CAPE worker/agent
    capture-signing adaptörü ve pinned anahtar ayrıca kurulup test edilmelidir.
9. **M9.9 — Broker bağlantı yapılandırması.** [x] `RE_BROKER_PROVIDER`,
   loopback/HTTPS base URL, broker ID, token environment variable, operator-pinned
   Ed25519 public-key digest ve remote HTTPS opt-in env örneği eklendi. Readiness
   yalnız GET base URL sağlık kontrolü yapar; task submit etmez. Credential
   çıktılarda redacted kalır. Canlı capture/signing adaptörü hâlâ yoktur.
   [x] Loopback-only test mock health endpoint eklendi; yalnız GET sağlık verir,
   POST/PUT 405 döndürür ve readiness `test_only` olarak işaretler. Bu, canlı
   broker/capture doğrulaması değildir.
10. **M9.10 — MCP araç yüzeyi.** [~] `oep_static_candidates` artık açık
   `oep_result` (Runtime OEP NOT VERIFIED) alanını döndürür; `oep_runtime_plan`
   bounded plan üretip broker readiness durumunu verir ve hiçbir örneği
   göndermez/çalıştırmaz. `oep_runtime_verify` plan hash'i yanında operator
   Ed25519 public-key hash pin'ini zorunlu tutarak kanıtı salt-okunur doğrular.
   Ortak istemciler için read-only
   `oep_static_candidates` (scan/show/export) ve ayrı onay kapılı
   `oep_runtime_plan`, `oep_runtime_start`, `oep_runtime_status`,
   `oep_runtime_trace`, `oep_runtime_dump`, `oep_runtime_export` araçları.
   Runtime araçları default/read-only profiline girmez; broker ID ve plan hash'i
   zorunludur. Keyfi PID, host path, shell, inject, bellek yazma veya genel VM
   console parametresi kabul edilmez.
11. **M9.11 — Test, ölçüm ve kabul.** Yetkili, temiz ve sentetik unpacker/OEP
    corpus; bilinen non-packed PE, TLS callback, overlay, malformed/truncated
    PE, high-entropy ama packed olmayan dosya, 32/64-bit, false-positive ve
    telemetry-loss vakaları kapsanır. Known ground truth ile precision/recall,
    aday başına kanıt kalitesi, süre/bellek/dump kotası ve tekrar üretilebilirlik
    ölçülür. Runtime feature GA sayılmadan önce izolasyon, approval, teardown,
    hash/provenance ve negatif senaryolar geçmelidir.

### M9 değişmez güvenlik sınırları

- `declared_ep`, statik `candidate` ve runtime `verified_oep` ayrı alanlardır;
  UI/rapor/API bunları tek bir “OEP” değeri altında birleştirmez.
- Statik OEP keşfi salt-okunur ve otomatik olabilir. Örnek çalıştırma, trace,
  process memory dump veya sandbox başlatma otomatik değildir; her run için
  kullanıcı onayı, snapshot, bütçe ve kayıtlı izole broker şarttır.
- İzolasyon/telemetry doğrulanamıyorsa runtime sonucu kesinleştirilmez. Host'ta
  örnek çalıştırma, in-place binary değişikliği, canlı process injection ve
  koruma atlatma bu özelliğin kapsamı dışındadır.
