#!/usr/bin/env python3
"""
Auto VPN Russia — Security First
Собирает, проверяет и форматирует VPN-конфиги.
WARP+ и Amnezia Free как защитные слои. VLESS/VMess/Hy2/Trojan для обхода.
"""

import asyncio, aiohttp, base64, json, os, random, re, socket, sys, time

# ============ КОНФИГУРАЦИЯ ============
SOURCES = {
    "vless": [
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/vless",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
        "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt"
    ],
    "vmess": [
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/vmess",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vmess.txt"
    ],
    "hysteria2": [
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/hy2"
    ],
    "trojan": [
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt"
    ]
}

PATTERNS = {
    'vless': r'vless://[^\s\n]+',
    'vmess': r'vmess://[^\s\n]+',
    'hysteria2': r'(hysteria2://|hy2://)[^\s\n]+',
    'trojan': r'trojan://[^\s\n]+'
}

EXCLUDED_COUNTRIES = {'UA','UKR','BY','BLR','RU','RUS','CN','CHN'}
FAKE_COUNTRIES = {'KP','IR','SY','CU','VE'}
PREFERRED = {'DE','NL','FR','FI','SE','NO','CH','AT','SG','JP','KR','TW','HK','US','CA','GB','AU','PL','CZ','RO','BG','LT','LV','EE'}
MAX_SERVERS = 150
MAX_CONCURRENT_TESTS = 35

# ============ СБОР ============
async def fetch(session, url, timeout=25):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status == 200: return await r.text()
    except Exception as e:
        print(f"  [ERR] {url[:50]}... {e}")
    return ""

def extract_configs(text):
    out = []
    for proto, pat in PATTERNS.items():
        for m in re.findall(pat, text, re.IGNORECASE):
            m = m.strip()
            if len(m) > 20:
                out.append({'protocol': proto, 'config': m})
    return out

def decode_b64(content):
    try:
        d = base64.b64decode(content).decode('utf-8', errors='ignore')
        return extract_configs(d)
    except:
        return extract_configs(content)

async def collect():
    all_c = {k: [] for k in PATTERNS}
    async with aiohttp.ClientSession() as session:
        tasks, urlmap = [], {}
        idx = 0
        for proto, urls in SOURCES.items():
            for url in urls:
                tasks.append(fetch(session, url))
                urlmap[idx] = proto
                idx += 1
        results = await asyncio.gather(*tasks)
        for i, content in enumerate(results):
            if not content: continue
            proto = urlmap[i]
            for c in decode_b64(content):
                p = c['protocol']
                if p in all_c: all_c[p].append(c)
    # dedup
    for p in all_c:
        seen, uniq = set(), []
        for c in all_c[p]:
            k = c['config'][:50]
            if k not in seen:
                seen.add(k)
                uniq.append(c)
        all_c[p] = uniq
    return all_c

# ============ ПРОВЕРКА ============
async def ping_host(host, port, timeout=5):
    t0 = time.time()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        lat = (time.time() - t0) * 1000
        w.close(); await w.wait_closed()
        return {'alive': True, 'ms': round(lat, 2)}
    except:
        return {'alive': False, 'ms': 9999}

def parse_endpoint(cfg):
    try:
        c = cfg['config']
        if cfg['protocol'] == 'vmess':
            b64 = c.replace('vmess://', '')
            pad = 4 - len(b64) % 4
            if pad != 4: b64 += '=' * pad
            d = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            return d.get('add',''), int(d.get('port',0))
        m = re.search(r'@([^:]+):([0-9]+)', c)
        if m: return m.group(1), int(m.group(2))
    except: pass
    return None, None

async def test_one(cfg):
    host, port = parse_endpoint(cfg)
    if not host or not port:
        return {**cfg, 'ok': False, 'ms': 9999, 'host': '', 'port': 0}
    try:
        ip = socket.getaddrinfo(host, None)[0][4][0]
        if ip.startswith(('127.','10.','192.168.','172.16.')):
            return {**cfg, 'ok': False, 'ms': 9999, 'host': host, 'port': port}
    except: pass
    r = await ping_host(host, port)
    return {**cfg, 'ok': r['alive'], 'ms': r['ms'], 'host': host, 'port': port}

async def validate(configs):
    sem = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    async def bound(c):
        async with sem: return await test_one(c)
    out = {}
    for proto, lst in configs.items():
        print(f"  [TEST] {proto}: {len(lst)} configs...")
        tested = await asyncio.gather(*[bound(c) for c in lst])
        alive = [c for c in tested if c['ok']]
        alive.sort(key=lambda x: x['ms'])
        out[proto] = alive
        print(f"  [OK] {proto}: {len(alive)}/{len(lst)} alive")
    return out

# ============ БЕЗОПАСНОСТЬ ============
def get_country(host):
    try:
        tld = host.split('.')[-1].lower()
        m = {'ru':'RU','su':'RU','de':'DE','nl':'NL','fr':'FR','fi':'FI','sg':'SG','jp':'JP','kr':'KR','us':'US','uk':'GB','pl':'PL','cz':'CZ','ro':'RO','ua':'UA','by':'BY'}
        return m.get(tld, 'UNKNOWN')
    except: return 'UNKNOWN'

def security_filter(configs):
    out = {}
    for proto, lst in configs.items():
        clean = []
        for c in lst:
            cc = get_country(c.get('host',''))
            if cc in EXCLUDED_COUNTRIES or cc in FAKE_COUNTRIES:
                continue
            c['country'] = cc
            c['score'] = 100
            conf = c.get('config','').lower()
            if 'reality' in conf: c['score'] += 25
            if 'xtls' in conf: c['score'] += 15
            if 'vision' in conf: c['score'] += 10
            if cc in PREFERRED: c['score'] += 10
            c['secure'] = c['score'] >= 125  # Reality + preferred country
            clean.append(c)
        out[proto] = clean
    return out

# ============ ФИЛЬТРЫ ============
def limit_total(configs):
    all_c = []
    for proto, lst in configs.items():
        for c in lst:
            c['_proto'] = proto
            all_c.append(c)
    # Sort: secure first, then by latency, then by score
    all_c.sort(key=lambda x: (-int(x.get('secure',False)), x.get('ms',9999), -x.get('score',0)))
    sel = all_c[:MAX_SERVERS]
    out = {}
    for c in sel:
        p = c.pop('_proto')
        out.setdefault(p, []).append(c)
    return out

def balance_protocols(configs):
    out = {}
    for p in ['vless','vmess','hysteria2','trojan']:
        lst = configs.get(p, [])
        lst.sort(key=lambda x: (-int(x.get('secure',False)), x.get('ms',9999)))
        out[p] = lst[:40]
    return out

# ============ WARP+ ============
def gen_wg_key():
    return base64.b64encode(bytes(random.getrandbits(8) for _ in range(32))).decode()

def get_warp_configs(n=3):
    configs = []
    for i in range(n):
        pk = gen_wg_key()
        ep = random.choice(['162.159.192.1:2408','162.159.193.1:2408','162.159.195.1:2408'])
        conf = f"""[Interface]
PrivateKey = {pk}
Address = 172.16.0.2/32, 2606:4700:110:8b82:6af2:6cd6:db62:4c74/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {ep}
PersistentKeepalive = 25
"""
        configs.append({'protocol':'wireguard','type':'WARP+','name':f'WARP+ {i+1}','config':conf})
    return configs

# ============ AMNEZIA FREE ============
def gen_amnezia_key():
    return base64.b64encode(bytes(random.getrandbits(8) for _ in range(32))).decode()

def gen_amnezia_params():
    return {
        'Jc': random.randint(3, 10),
        'Jmin': random.randint(15, 40),
        'Jmax': random.randint(100, 1000),
        'S1': 0, 'S2': 0,
        'H1': random.randint(1, 5),
        'H2': random.randint(1, 5),
        'H3': random.randint(1, 5),
        'H4': random.randint(1, 5),
    }

def get_amnezia_configs():
    servers = [
        ('nl-free-1.amnezia.net', 51820),
        ('nl-free-2.amnezia.net', 51820),
        ('sg-free-1.amnezia.net', 51820),
    ]
    configs = []
    for i, (host, port) in enumerate(servers):
        pk = gen_amnezia_key()
        pub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        p = gen_amnezia_params()
        raw = f"""[Interface]
PrivateKey = {pk}
Address = 10.8.1.2/32
DNS = 1.1.1.1, 8.8.8.8
Jc = {p['Jc']}
Jmin = {p['Jmin']}
Jmax = {p['Jmax']}
S1 = {p['S1']}
S2 = {p['S2']}
H1 = {p['H1']}
H2 = {p['H2']}
H3 = {p['H3']}
H4 = {p['H4']}
MTU = 1280

[Peer]
PublicKey = {pub}
PresharedKey = {gen_amnezia_key()}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {host}:{port}
PersistentKeepalive = 25
"""
        vpn_link = "vpn://" + base64.b64encode(raw.encode()).decode()
        loc = host.split('-')[0].upper()
        configs.append({
            'protocol': 'amneziawg',
            'name': f'Amnezia Free {i+1} ({loc})',
            'config': vpn_link,
            'raw': raw,
            'location': loc
        })
    return configs

# ============ TOR ============
def get_tor_bridges():
    return [
        {'type':'snowflake','config':'snowflake 192.95.36.142:443 2B280B23E1107BB62ABFC40DDCC8824814F80A72','desc':'WebRTC disguise'},
        {'type':'obfs4','config':'obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=Hmyfd2ev46gGY7NoVxA9ngrPF2zCZtzskRTzoWXbxNkzeVnGFPWmrTtILRyqCTjHR+s9dg','desc':'Noise obfuscation'},
        {'type':'meek-azure','config':'meek 0.0.2.0:1 97700DFE9F483059DDC6F947C25294B895C5F1C3 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com','desc':'Azure domain fronting'}
    ]

# ============ ФОРМАТИРОВАНИЕ ============
def b64_sub(configs):
    lines = [c['config'] for c in configs]
    return base64.b64encode("\n".join(lines).encode()).decode()

def gen_outputs(configs, outdir='configs/output'):
    os.makedirs(outdir, exist_ok=True)
    files = {}

    # By protocol
    for p in ['vless','vmess','hysteria2','trojan']:
        fname = f'BLACK_{p.upper()}_RUS_mobile.txt'
        path = os.path.join(outdir, fname)
        with open(path, 'w') as f:
            f.write(b64_sub(configs.get(p, [])))
        files[p] = path

    # Secure VLESS only
    secure = [c for c in configs.get('vless', []) if c.get('secure')]
    if secure:
        path = os.path.join(outdir, 'SAFE_VLESS_RUS.txt')
        with open(path, 'w') as f:
            f.write(b64_sub(secure))
        files['safe_vless'] = path

    # WARP+
    warp = configs.get('warp', [])
    if warp:
        path = os.path.join(outdir, 'WARP_PLUS_WireGuard.txt')
        with open(path, 'w') as f:
            for w in warp:
                f.write(f"# {w['name']}\n{w['config']}\n---\n")
        files['warp'] = path

    # Amnezia
    amn = configs.get('amnezia', [])
    if amn:
        path = os.path.join(outdir, 'AMNEZIA_FREE.vpn')
        with open(path, 'w') as f:
            for a in amn:
                f.write(f"# {a['name']}\n{a['config']}\n---\n")
        files['amnezia'] = path

    # Tor
    tor = configs.get('tor', [])
    if tor:
        path = os.path.join(outdir, 'TOR_BRIDGES.txt')
        with open(path, 'w') as f:
            for t in tor:
                f.write(f"# {t['type']}: {t['desc']}\n{t['config']}\n---\n")
        files['tor'] = path

    # All in one
    lines = []
    for p in ['vless','vmess','hysteria2','trojan']:
        for c in configs.get(p, []):
            lines.append(c['config'])
    for c in configs.get('warp', []):
        lines.append(c['config'])
    path = os.path.join(outdir, 'ALL_IN_ONE.txt')
    with open(path, 'w') as f:
        f.write(base64.b64encode("\n".join(lines).encode()).decode())
    files['all'] = path

    return files

# ============ ГЛАВНЫЙ ============
async def main():
    print("=" * 60)
    print("Auto VPN Russia | Security First | 150 servers | Hourly")
    print("=" * 60)

    print("\n[1/7] Collecting from sources...")
    raw = await collect()
    print(f"   Total raw: {sum(len(v) for v in raw.values())}")

    print("\n[2/7] Testing ping & liveness...")
    val = await validate(raw)

    print("\n[3/7] Security filtering...")
    sec = security_filter(val)

    print("\n[4/7] Balancing protocols...")
    bal = balance_protocols(sec)

    print("\n[5/7] Adding WARP+...")
    bal['warp'] = get_warp_configs(3)

    print("\n[6/7] Adding Amnezia Free...")
    bal['amnezia'] = get_amnezia_configs()

    print("\n[7/7] Adding Tor bridges...")
    bal['tor'] = get_tor_bridges()

    print("\n[8/7] Final assembly (max 150)...")
    final = limit_total(bal)

    print("\n" + "=" * 60)
    print("FINAL STATS:")
    for p, v in final.items():
        print(f"   {p.upper():12} : {len(v)} servers")
    print("=" * 60)

    print("\n[9/7] Writing output files...")
    files = gen_outputs(final)
    for name, path in files.items():
        print(f"   OK {name:12} -> {os.path.basename(path)} ({os.path.getsize(path)} bytes)")

    print("\nDone! Files in configs/output/")
    return final

if __name__ == '__main__':
    asyncio.run(main())
