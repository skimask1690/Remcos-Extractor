# 🧩 Remcos Extractor

A tool to **decrypt, parse, and re‑encrypt Remcos RAT configuration** embedded in Remcos binaries.

---

## 🔹 Features
- 🔓 **Decrypt** the RC4‑encrypted `SETTINGS` resource from Remcos binaries  
- 📜 **Parse** and display config fields with names, descriptions, and values  
- 🔒 **Re‑encrypt** modified configs back into a new PE file  

---

## 🔹 Usage

```bash
python remcos_extractor.py [mode] <args>
```

### Decrypt config
```bash
python remcos_extractor.py -d remcos.exe config.cfg
```

### Parse config
```bash
python remcos_extractor.py -p config.cfg
```

### Re‑encrypt config
```bash
python remcos_extractor.py -e remcos.exe config.cfg new_remcos.exe
```
---

## 🔹 Requirements
```bash
pip install pefile pycryptodome
```
---

## 🔹 References
The configuration field offsets and descriptions are based on the analysis in  
➡️ [Elastic Security Labs – Dissecting Remcos RAT (Part Three)](https://www.elastic.co/security-labs/dissecting-remcos-rat-part-three)

---

## ⚠️ Disclaimer
This tool is provided for educational and research purposes only. The author is not responsible for any misuse.
