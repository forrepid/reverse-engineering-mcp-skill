# Reverse Engineering Companion MCP

IDA Pro/IDALib, Ghidra ve sekiz MCP istemcisi için kanıt odaklı, modüler tersine
mühendislik skill'i, yerel CLI ve salt-okunur MCP yardımcı sunucusu.

Kurulum, ortam değişkenleri, komutlar ve host bağlantıları için [SKILL.md](SKILL.md)
dosyasından başlayın. Değişmez proje kuralları ve kayıt sözleşmesi üst dizindeki
[`maincontrat.md`](../maincontrat.md) dosyasındadır.

## Hızlı kurulum (PowerShell)

```powershell
cd "C:\Users\beessy\Documents\rce mpc oluşturma\reverse-engineering"
uv sync --extra dev
.\.venv\Scripts\re-cli.exe env-check --env-file .env.example
.\.venv\Scripts\re-cli.exe feature-check
.\.venv\Scripts\re-cli.exe doctor `
  --ida "C:\Program Files\IDA Professional 9.4\ida.exe" `
  --idalib-mcp "C:\Users\beessy\AppData\Local\Programs\Python\Python313\Scripts\idalib-mcp.exe" `
  --ghidra-home "C:\Users\beessy\Tools\ghidra_12.1.2_PUBLIC" `
  --ghidra-bridge "C:\Users\beessy\Tools\GhidraMCP\bridge_mcp_ghidra.py"
.\.venv\Scripts\re-mcp-server.exe --check
```

MCP istemci ayarları ve IDA/Ghidra köprüleri için
[`references/client-integration.md`](references/client-integration.md), tüm komutlar
için [`references/command-reference.md`](references/command-reference.md) dosyasını
kullanın. Örnek dosya yollarını kendi kurulumunuza göre değiştirin.

Bu iş istasyonunda Ghidra 12.1.2, Microsoft OpenJDK 21 ve GhidraMCP'nin pinned
12.1.2 build'i kuruludur. CodeBrowser etkinleştirmesi kaydedilmiş ve canlı
`python.exe` Program'ı üç read-only MCP çağrısıyla doğrulanmıştır. Başka bir
makinedeki tek seferlik GUI etkinleştirmesi ve yeniden üretilebilir build için
[`references/ghidra-12.1.2.md`](references/ghidra-12.1.2.md) belgesini kullanın.

## Güvenlik sınırı

Companion sunucusu örnek çalıştırmaz, internete yüklemez ve doğrudan patch yazmaz.
Patch/source değişiklikleri hash ile mühürlenmiş plan ve yeni çıktı dosyası gerektirir.
IDA/Ghidra üzerinde değişiklik yapan araçlar companion'dan ayrı host MCP onaylarına
tabidir.
