import ipaddress
import json
import os
import re2
import ssl
import subprocess
import urllib.error
import urllib.request

RE2_OPTIONS = re2.Options()
RE2_OPTIONS.log_errors = False

RULES_DIR = "rules"
FETCH_TIMEOUT = 15
COMPILE_TIMEOUT = 60

FIELD_ORDER = ["domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"]

WATERMARK_PATTERNS = ["skk.moe"]

CATEGORIES = [
    {
        "name": "geosite-cn",
        "source_file": "geosite-cn.txt",
        "allowed_keys": {"domain", "domain_suffix", "domain_keyword", "domain_regex"},
    },
    {
        "name": "geosite-!cn",
        "source_file": "geosite-!cn.txt",
        "allowed_keys": {"domain", "domain_suffix", "domain_keyword", "domain_regex"},
    },
    {
        "name": "geosite-ad",
        "source_file": "geosite-ad.txt",
        "allowed_keys": {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"},
    },
    {
        "name": "geoip-cn",
        "source_file": "geoip-cn.txt",
        "allowed_keys": {"ip_cidr"},
    },
    {
        "name": "geoip-!cn",
        "source_file": "geoip-!cn.txt",
        "allowed_keys": {"ip_cidr"},
    },
]


def load_urls(filename):
    path = os.path.join(RULES_DIR, filename)
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)
    return urls


def is_watermark_value(value):
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(pattern in lowered for pattern in WATERMARK_PATTERNS)


def is_valid_regex(pattern):
    try:
        re2.compile(pattern, options=RE2_OPTIONS)
        return True
    except re2.error:
        return False


def process_urls(urls, allowed_keys, ssl_context):
    master_rules = {}
    dropped_keys = set()
    watermark_count = 0

    for url in urls:
        url = url.strip()
        if not url:
            continue

        try:
            print(f"  Fetching: {url}")

            with urllib.request.urlopen(url, context=ssl_context, timeout=FETCH_TIMEOUT) as response:
                raw = response.read().decode("utf-8")

            data = json.loads(raw)

            if not (isinstance(data, dict) and isinstance(data.get("rules"), list)):
                print(f"  [WARN] {url}: unexpected structure, no 'rules' list found, skipped")
                continue

            for rule in data["rules"]:
                if not isinstance(rule, dict):
                    print(f"  [WARN] {url}: rule entry is not an object, skipped ({rule!r})")
                    continue

                for key, value in rule.items():
                    if key not in allowed_keys:
                        dropped_keys.add(key)
                        continue

                    master_rules.setdefault(key, [])

                    if isinstance(value, list):
                        for item in value:
                            if is_watermark_value(item):
                                watermark_count += 1
                                continue
                            master_rules[key].append(item)
                    else:
                        if is_watermark_value(value):
                            watermark_count += 1
                        else:
                            master_rules[key].append(value)

        except urllib.error.URLError as e:
            print(f"  [NETWORK ERROR] {url}: {e}")
        except json.JSONDecodeError as e:
            print(f"  [JSON ERROR] {url}: invalid JSON ({e})")
        except Exception as e:
            print(f"  [ERROR] {url}: {e}")

    if dropped_keys:
        print(f"  [INFO] Ignored unknown/unsupported keys from this batch: {sorted(dropped_keys)}")

    if watermark_count:
        print(f"  [INFO] Filtered out {watermark_count} watermark/tracking domain(s)")

    return master_rules


def sort_ip_list(values):
    ipv4_seen = {}
    ipv6_seen = {}

    invalid_count = 0
    non_str_count = 0

    for v in values:
        if not isinstance(v, str):
            non_str_count += 1
            continue

        v = v.strip()
        if not v:
            continue

        try:
            ip_obj = ipaddress.ip_network(v, strict=False)
        except Exception:
            invalid_count += 1
            continue

        if isinstance(ip_obj, ipaddress.IPv4Network):
            ipv4_seen[ip_obj] = None
        else:
            ipv6_seen[ip_obj] = None

    if non_str_count:
        print(f"  [WARN] ip_cidr: dropped {non_str_count} non-string value(s)")
    if invalid_count:
        print(f"  [WARN] ip_cidr: dropped {invalid_count} invalid/unparseable value(s)")

    ipv4_collapsed = list(ipaddress.collapse_addresses(ipv4_seen.keys()))
    ipv6_collapsed = list(ipaddress.collapse_addresses(ipv6_seen.keys()))

    ipv4_sorted = sorted(ipv4_collapsed, key=lambda x: (int(x.network_address), x.prefixlen))
    ipv6_sorted = sorted(ipv6_collapsed, key=lambda x: (int(x.network_address), x.prefixlen))

    return [str(x) for x in ipv4_sorted + ipv6_sorted]


def safe_sorted_unique(values, field_name):
    str_values = []
    non_str_count = 0
    invalid_regex_count = 0

    for v in values:
        if not isinstance(v, str):
            non_str_count += 1
            continue
        if field_name == "domain_regex" and not is_valid_regex(v):
            invalid_regex_count += 1
            continue
        str_values.append(v)

    if non_str_count:
        print(f"  [WARN] field '{field_name}': dropped {non_str_count} non-string value(s)")
    if invalid_regex_count:
        print(f"  [WARN] field '{field_name}': dropped {invalid_regex_count} invalid regex value(s)")

    return sorted(set(str_values))


def save_json_and_compile(master_rules, json_file, srs_file, allowed_keys):
    final_rule = {}

    for key in FIELD_ORDER:
        if key == "ip_cidr" or key not in allowed_keys:
            continue
        values = master_rules.get(key)
        if not values:
            continue
        final_rule[key] = safe_sorted_unique(values, key)

    if "ip_cidr" in allowed_keys:
        ip_values = master_rules.get("ip_cidr")
        if ip_values:
            final_rule["ip_cidr"] = sort_ip_list(ip_values)

    data = {
        "version": 5,
        "rules": [final_rule],
    }

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  JSON saved: {json_file}")

    try:
        result = subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", srs_file, json_file],
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )

        if result.returncode == 0:
            print(f"  SRS compiled: {srs_file}")
        else:
            print(f"  [SRS ERROR]: {result.stderr}")

    except FileNotFoundError:
        print("  [WARNING] sing-box not found, only JSON generated")
    except subprocess.TimeoutExpired:
        print(f"  [SRS ERROR]: compile timed out after {COMPILE_TIMEOUT}s")


def main():
    ssl_context = ssl.create_default_context()

    for category in CATEGORIES:
        name = category["name"]
        print(f"\n=== {name.upper()} ===")

        urls = load_urls(category["source_file"])
        merged = process_urls(urls, category["allowed_keys"], ssl_context)

        save_json_and_compile(
            merged,
            f"{name}.json",
            f"{name}.srs",
            category["allowed_keys"],
        )

    print("\n=== ALL DONE ===")


if __name__ == "__main__":
    main()
