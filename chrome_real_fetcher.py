#!/usr/bin/env python3
"""
chrome_real_fetcher.py
Descarga chrome.dll del instalador real de Chrome via Omaha API.

Requisitos: pip install requests pefile py7zr capstone
"""
import sys, io, uuid, json, struct, re, zipfile, tempfile, os
import requests, pefile, py7zr

# ── Omaha API ────────────────────────────────────────────────────────────────

OMAHA_URL    = "https://update.googleapis.com/service/update2/json"
CHROME_APPID = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"

CHANNELS = {
    "stable": "",
    "beta":   "1.1-beta",
    "dev":    "2.0-dev",
    "canary": "3.0-canary",
}

def query_omaha(channel="stable", current_version="0.0.0.0"):
    """Consulta Omaha y retorna (version, url_del_paquete)."""
    payload = {
        "request": {
            "@os": "win",
            "@updater": "chromeupdater",
            "acceptformat": "crx3,download",
            "app": [{
                "appid":       CHROME_APPID,
                "ap":          CHANNELS[channel],
                "version":     current_version,
                "lang":        "en-US",
                "brand":       "GGLS",
                "updatecheck": {}
            }],
            "hw":           {"physmemory": 16},
            "ismachine":    "0",
            "os":           {"arch": "x64", "platform": "Windows",
                             "version": "10.0.19045.0"},
            "protocol":     "3.1",
            "requestid":    "{" + str(uuid.uuid4()).upper() + "}",
            "sessionid":    "{" + str(uuid.uuid4()).upper() + "}",
            "updaterversion": "1.3.36.352"
        }
    }
    r = requests.post(OMAHA_URL, json=payload, timeout=30)
    r.raise_for_status()

    # Omaha antepone )]}'  para prevenir JSON hijacking
    text = r.text.lstrip()
    if text.startswith(")]}'"):
        text = text[4:]
    data = json.loads(text)

    app = data["response"]["app"][0]

    if app.get("updatecheck", {}).get("status") == "noupdate":
        print(f"  [{channel}] Ya en la última versión: {current_version}")
        return current_version, None

    manifest = app["updatecheck"]["manifest"]
    version  = manifest["version"]
    url_base = app["updatecheck"]["urls"]["url"][0]["codebase"]
    pkg_name = manifest["packages"]["package"][0]["name"]
    url      = url_base + pkg_name

    return version, url

# ── Descarga ─────────────────────────────────────────────────────────────────

def download_with_progress(url: str, session) -> bytes:
    r = session.get(url, stream=True, timeout=300)
    r.raise_for_status()
    total = int(r.headers.get("Content-Length", 0))
    buf   = bytearray()
    for chunk in r.iter_content(512 * 1024):
        buf += chunk
        if total:
            pct = len(buf) / total * 100
            mb  = len(buf) / 1024 / 1024
            tot = total / 1024 / 1024
            print(f"\r  Descargando... {pct:5.1f}%  ({mb:.0f}/{tot:.0f} MB)",
                  end="", flush=True)
        else:
            mb = len(buf) / 1024 / 1024
            print(f"\r  Descargando... {mb:.0f} MB", end="", flush=True)
    print()
    return bytes(buf)

# ── CRX3 parser ──────────────────────────────────────────────────────────────
# Formato CRX3:
#   4 bytes  magic    "Cr24"
#   4 bytes  version  (uint32 LE) = 3
#   4 bytes  hdr_size (uint32 LE)
#   hdr_size bytes   protobuf SignedData  (ignoramos)
#   resto:   ZIP payload

CRX3_MAGIC = b"Cr24"

def crx3_to_zip(data: bytes) -> bytes | None:
    if data[:4] != CRX3_MAGIC:
        return None
    hdr_size = struct.unpack_from("<I", data, 8)[0]
    zip_offset = 12 + hdr_size
    payload = data[zip_offset:]
    if payload[:2] == b"PK":
        print(f"  [+] CRX3 parseado: ZIP @ offset {zip_offset:#x} "
              f"({len(payload)/1024/1024:.1f} MB)")
        return payload
    return None

# ── Extractor principal ───────────────────────────────────────────────────────

def extract_chrome_dll(pkg_data: bytes) -> bytes | None:
    """
    Recibe el paquete descargado (CRX3, ZIP, 7z, o PE) y extrae chrome.dll.
    Estructura habitual:
      CRX3 → ZIP → chrome.7z → Chrome-bin/{ver}/chrome.dll
      CRX3 → ZIP → chrome.dll  (builds compactos)
    """

    # 1. Desempaquetar CRX3 → ZIP si aplica
    if pkg_data[:4] == CRX3_MAGIC:
        zip_data = crx3_to_zip(pkg_data)
        if zip_data:
            return extract_from_zip(zip_data)
        print("  [!] CRX3 parseado pero payload no es ZIP")
        return None

    # 2. ZIP directo
    if pkg_data[:2] == b"PK":
        return extract_from_zip(pkg_data)

    # 3. 7z directo
    if pkg_data[:6] == b"7z\xbc\xaf\x27\x1c":
        return extract_from_7z(pkg_data)

    # 4. PE (mini_installer clásico)
    return extract_from_pe(pkg_data)


def extract_from_zip(zip_data: bytes) -> bytes | None:
    """Busca chrome.dll, .7z o .exe instalador dentro de un ZIP."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            names = z.namelist()
            print(f"  [+] ZIP con {len(names)} archivos: {names}")

            # chrome.dll directo
            for n in names:
                if n.lower().endswith("chrome.dll"):
                    print(f"  [+] chrome.dll directo en ZIP: {n}")
                    return z.read(n)

            # .7z interno
            for n in names:
                if n.lower().endswith(".7z"):
                    print(f"  [+] Abriendo {n} dentro del ZIP...")
                    inner = z.read(n)
                    result = extract_from_7z(inner)
                    if result:
                        return result

            # .exe instalador (ej: 155.0.x_chrome_installer_uncompressed.exe)
            # Contiene chrome.dll embebido como recurso o 7z appended
            for n in names:
                if n.lower().endswith(".exe") and "chrome" in n.lower():
                    print(f"  [+] Extrayendo instalador: {n}")
                    exe_data = z.read(n)
                    print(f"      Tamaño: {len(exe_data)/1024/1024:.1f} MB  "
                          f"(magic: {exe_data[:4]})")
                    result = extract_from_pe(exe_data)
                    if result:
                        return result

    except Exception as e:
        print(f"  [!] Error leyendo ZIP: {e}")
    return None


def extract_from_7z(data: bytes, depth=0) -> bytes | None:
    """Busca chrome.dll recursivamente en archivos 7z anidados."""
    prefix = "  " * (depth + 1)
    try:
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as z:
            names = z.getnames()
            print(f"{prefix}7z nivel {depth}: {len(names)} archivos, "
                  f"primeros: {names[:6]}")

            dll_names  = [n for n in names if n.lower().endswith("chrome.dll")]
            inner_7z   = [n for n in names if n.lower().endswith(".7z")]
            targets    = dll_names + inner_7z

            if not targets:
                print(f"{prefix}[!] Sin chrome.dll ni .7z internos")
                return None

            # Extraer solo los archivos que necesitamos a un dir temporal
            with tempfile.TemporaryDirectory() as tmpdir:
                with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as z2:
                    z2.extract(path=tmpdir, targets=targets)

                # chrome.dll encontrado
                for n in dll_names:
                    fpath = os.path.join(tmpdir, n.replace("/", os.sep))
                    if os.path.exists(fpath):
                        with open(fpath, "rb") as f:
                            content = f.read()
                        print(f"{prefix}✓ chrome.dll: {len(content)/1024/1024:.1f} MB")
                        return content

                # .7z interno → recursión
                for n in inner_7z:
                    fpath = os.path.join(tmpdir, n.replace("/", os.sep))
                    if os.path.exists(fpath):
                        print(f"{prefix}→ Abriendo {n}...")
                        with open(fpath, "rb") as f:
                            inner_data = f.read()
                        found = extract_from_7z(inner_data, depth + 1)
                        if found:
                            return found

    except Exception as e:
        print(f"{prefix}[!] Error 7z: {e}")
    return None


def extract_from_pe(pe_data: bytes) -> bytes | None:
    """Extrae el payload 7z embebido en un mini_installer.exe."""
    MAGIC_7Z = b"7z\xbc\xaf\x27\x1c"
    try:
        pe = pefile.PE(data=pe_data)
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if rtype.id in (0xB7, 183, 10):
                    for rname in rtype.directory.entries:
                        for rlang in rname.directory.entries:
                            rva  = rlang.data.struct.OffsetToData
                            size = rlang.data.struct.Size
                            res  = pe.get_data(rva, size)
                            if res.startswith(MAGIC_7Z):
                                print(f"  [+] Recurso 7z en PE ({size/1024/1024:.1f}MB)")
                                return extract_from_7z(res)
    except Exception as e:
        print(f"  [!] pefile: {e}")

    # Fallback scan
    idx = pe_data.find(MAGIC_7Z)
    if idx != -1:
        print(f"  [+] 7z por scan @ offset {idx:#x}")
        return extract_from_7z(pe_data[idx:])

    return None

# ── Salt extractor (v2) ───────────────────────────────────────────────────────

ANCHOR_STR  = b"X-Browser-Validation\x00"
SALT_RE     = re.compile(rb"[0-9a-f]{16}\x00")
EXCLUDE     = {b"0000000000000000", b"ffffffffffffffff",
               b"0123456789abcdef", b"f8f9fafbfcfdfeff"}
PROXIMITY   = 0x1000
SCAN_RADIUS = 0x6000

def extract_salt_from_bytes(dll_bytes):
    import capstone
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    # ── 1. Parsear PE ────────────────────────────────────────────────────────
    try:
        pe = pefile.PE(data=dll_bytes)
    except Exception as e:
        print(f"  [!] pefile falló: {e}")
        return None

    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode(errors='replace'),
             base + s.VirtualAddress, s.get_data())
            for s in pe.sections]
    print(f"  [d] PE base={base:#x}, secciones: "
          f"{[n for n,_,_ in secs]}")

    # ── 2. Buscar anchor ─────────────────────────────────────────────────────
    anchor_va = None
    for name, va, data in secs:
        off = data.find(ANCHOR_STR)
        if off != -1:
            anchor_va = va + off
            print(f"  [d] Anchor en sección '{name}' @ {anchor_va:#x}")
            break

    if not anchor_va:
        # Intentar búsqueda cruda por si las secciones no cargan bien
        raw_off = dll_bytes.find(ANCHOR_STR)
        print(f"  [!] Anchor no encontrado en secciones PE.")
        if raw_off != -1:
            print(f"      ¿Encontrado raw @ offset {raw_off:#x}? "
                  f"Puede que pefile no esté leyendo bien las secciones.")
        else:
            print(f"      Tampoco en raw — ¿es esta la chrome.dll correcta?")
        return None

    # ── 3. Candidatos a salt ─────────────────────────────────────────────────
    all_hex = {}
    for _, va, data in secs:
        for m in SALT_RE.finditer(data):
            all_hex[va + m.start()] = m.group(0)[:-1]

    candidates = {
        va: v for va, v in all_hex.items()
        if abs(va - anchor_va) <= PROXIMITY and v not in EXCLUDE
    }
    print(f"  [d] {len(all_hex)} strings hex-16 totales, "
          f"{len(candidates)} dentro de ±{PROXIMITY:#x} del anchor")

    if not candidates:
        # Mostrar los más cercanos para debug
        nearest = sorted(all_hex.items(),
                         key=lambda x: abs(x[0] - anchor_va))[:5]
        print(f"  [d] Más cercanos al anchor:")
        for va, v in nearest:
            print(f"      {va:#x}  ({va - anchor_va:+#x})  {v.decode()}")
        candidates = {va: v for va, v in all_hex.items() if v not in EXCLUDE}
        print(f"  [!] Usando todos los candidatos ({len(candidates)}), "
              f"considera aumentar PROXIMITY")

    # ── 4. Buscar referencias en .text ───────────────────────────────────────
    text_entry = next(((n, va, d) for n, va, d in secs
                       if b".text" in n.encode()), None)
    if not text_entry:
        print(f"  [!] Sección .text no encontrada")
        return None

    _, text_va, text_data = text_entry
    text_end = text_va + len(text_data)

    def find_lea_refs(data, sec_va, target):
        for i in range(len(data) - 7):
            if (data[i] & 0xF8 == 0x48 and data[i+1] == 0x8D
                    and (data[i+2] & 0xC7) == 0x05):
                va = sec_va + i
                d  = struct.unpack_from("<i", data, i+3)[0]
                if va + 7 + d == target:
                    yield va

    refs = list(find_lea_refs(text_data, text_va, anchor_va))
    print(f"  [d] {len(refs)} referencias LEA al anchor en .text")
    if not refs:
        print(f"  [!] Sin referencias — puede que el anchor esté en .rdata2 "
              f"o el compilador usó otra instrucción")
        return None

    # ── 5. Buscar referencias directas al salt en todo .text ─────────────────
    # Estrategia: raw scan O(n) de disp32 → mucho más rápido que Capstone
    # para barrer 100+ MB de .text.
    # Para cada candidato, buscamos bytes donde:
    #   insn_end_va + disp32 == salt_va
    # Luego verificamos con Capstone que es una instrucción válida.

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    for salt_va, salt_bytes in candidates.items():
        print(f"  [d] Buscando refs al salt {salt_bytes.decode()} "
              f"@ {salt_va:#x} en todo .text ({len(text_data)//1024//1024}MB)...")

        # Raw scan: busca cada posición donde disp32 apunta a salt_va
        hit_offsets = []
        target = salt_va
        for i in range(len(text_data) - 4):
            insn_end_va = text_va + i + 4
            disp = struct.unpack_from("<i", text_data, i)[0]
            if insn_end_va + disp == target:
                hit_offsets.append(text_va + i)

        print(f"  [d] {len(hit_offsets)} posibles refs raw al salt")

        # Verificar con Capstone: retroceder hasta 15 bytes y desensamblar
        for hit_va in hit_offsets:
            # El disp32 termina en hit_va+4; la instrucción puede empezar
            # hasta 15 bytes antes (longitud máxima de instrucción x86)
            scan_start = max(text_va, hit_va - 11)
            chunk = text_data[scan_start - text_va : hit_va - text_va + 8]
            for insn in md.disasm(chunk, scan_start):
                insn_end = insn.address + insn.size
                if insn_end - 4 <= hit_va < insn_end:
                    for op in insn.operands:
                        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                            resolved = insn.address + insn.size + op.mem.disp
                            if resolved == target:
                                print(f"  [d] Confirmado por Capstone: "
                                      f"{insn.address:#x} {insn.mnemonic} {insn.op_str}")
                                return salt_bytes.decode(), salt_va, insn

    return None

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--channel", choices=CHANNELS, default="stable",
                   help="Canal de Chrome (default: stable)")
    p.add_argument("--save-dll",  metavar="FILE", help="Guardar chrome.dll")
    p.add_argument("--save-pkg",  metavar="FILE", help="Guardar paquete descargado (CRX3/ZIP)")
    args = p.parse_args()

    session = requests.Session()
    session.headers["User-Agent"] = "GoogleUpdate/1.3.36.352"

    # 1. Consultar Omaha
    print(f"[*] Consultando Omaha API (canal: {args.channel})...")
    version, url = query_omaha(args.channel)
    if not url:
        sys.exit(0)
    print(f"[+] Versión : {version}")
    print(f"[+] URL     : {url}")
    print(f"[+] Formato : {url.split('.')[-1].upper()}")

    # 2. Descargar
    print(f"[*] Descargando paquete...")
    pkg_bytes = download_with_progress(url, session)
    print(f"[+] Descargado: {len(pkg_bytes)/1024/1024:.1f} MB  "
          f"(magic: {pkg_bytes[:4]})")

    if args.save_pkg:
        with open(args.save_pkg, "wb") as f:
            f.write(pkg_bytes)
        print(f"[+] Guardado en {args.save_pkg}")

    # 3. Extraer chrome.dll
    print(f"[*] Extrayendo chrome.dll...")
    dll_bytes = extract_chrome_dll(pkg_bytes)
    if not dll_bytes:
        print("[-] chrome.dll no encontrado")
        print("    Usa --save-pkg para inspeccionar el paquete manualmente")
        sys.exit(1)

    if args.save_dll:
        with open(args.save_dll, "wb") as f:
            f.write(dll_bytes)
        print(f"[+] chrome.dll guardado en {args.save_dll}")

    # 4. Extraer salt
    print(f"[*] Extrayendo salt...")
    result = extract_salt_from_bytes(dll_bytes)

    if result:
        salt, salt_va, insn = result
        print(f"\n{'='*55}")
        print(f"  Chrome version  : {version}  [{args.channel}]")
        print(f"  Salt            : {salt}")
        print(f"  VA del string   : {salt_va:#x}")
        print(f"  Instrucción     : {insn.address:#x}  {insn.mnemonic} {insn.op_str}")
        print(f"{'='*55}")
    else:
        print("[-] Salt no encontrado en chrome.dll")

if __name__ == "__main__":
    main()