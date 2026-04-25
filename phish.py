import warnings
warnings.filterwarnings("ignore")
from urllib.parse import urlsplit
from string import punctuation
import tldextract
import math
import whois
from datetime import datetime, timezone

#--- Threshold & Scoring ----
HOSTNAME_LENGTH_THRESHOLD = 20
SUBDOMAIN_COUNT_THRESHOLD = 4
SLASH_THRESHOLD = 5 
DOT_THRESHOLD = 4 
DOMAIN_AGE_THRESHOLD_DAYS = 180
ENTROPY_THRESHOLD = 3 
BRAND_EDIT_DISTANCE = 2 
HIGH_RISK_SCORE = 1
SUSPICIOUS_SCORE = 0.7
STANDARD_PORTS = {80,443, None}

#---Known Brands -----
know_brands = [
    "paypal",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "microsoft",
    "gmail",
    "ebay",
    "X",
    "linkedin",
    "yahoo",
    "spotify",
    "coinbase",
    "dropbox",
    "tiktok"
]

suspicious_tld = [
    "tkl",
    "ml",
    "ga",
    "cf",
    "gq",
    "pw",
    "top",
    "xyz",
    "tk",
    "zip",
    "mov",
    "info",
    "biz",
    "click",
    "link",
    "live",
    "online"
   
]

# ── URL shortener domains ────────────────────────────────────────────────────
url_shorteners = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "shorturl.at", "is.gd", "rebrand.ly", "cutt.ly",
]

# ── Suspicious path/query keywords ──────────
suspicious_keywords = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "banking", "password",
    "confirm", "credential", "wallet", "recover", "unlock",
]

def urlDissection(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    result = urlsplit(url)

    components = {
        'scheme' : result.scheme,
        'hostname' : result.hostname,
        'port' : result.port,
        'query' : result.query,
        'fragment' : result.fragment,
        'path': result.path
    }
    
    netlockDissection = tldextract.extract(result.netloc)
    components["domain"] = netlockDissection.domain
    components["subdomain"] = netlockDissection.subdomain
    components["top level domain"] = netlockDissection.suffix

    return components

# –– Detect functions –––––

def termsInHostname(components):
    
    hostname = components.get("hostname")
    if not hostname:
        return False 
    return len(hostname.split(".")) > SUBDOMAIN_COUNT_THRESHOLD
    

def lengthOfHostDomain(components):

    hostname = components.get("hostname")
    if not hostname:
        return False 
    return len(hostname) > HOSTNAME_LENGTH_THRESHOLD

def numberOfSlashes(url):
    return url.count("/") >= SLASH_THRESHOLD

def dotsHostname(components):
    hostname = components.get("hostname")
    if not hostname:
        return False
    return hostname.count(".") > DOT_THRESHOLD

def specialCharacterInHost(components):
    hostname = components.get("hostname")
    if not hostname:
        return False 
    for ch in hostname:
        if ch != "." and ch in punctuation:
            return True
    return False
    
def IPinURL(components):
    hostname = components.get("hostname")
    if not hostname:
        return False 
    
    parts = hostname.split(".")

    if len(parts) != 4:
        return False
    
    for part in parts:
        if not part.isdigit():
            return False
        
        num = int(part)
        if not (num >= 0 and num <=255):
            return False
    return True


def unicodeURL(components):
    hostname = components.get("hostname")
    if not hostname:
        return False 
    if "xn--" in hostname:
        return True
    try:
        punycode = hostname.encode('idna').decode('ascii')
        return "xn--" in punycode
    except (UnicodeError, UnicodeDecodeError):
        return True
    
def tld_check(components):
    tld = components.get("top level domain")
    return tld in suspicious_tld

def dp(domain, brand):
    """Levenshtein edit distance between domain and brand."""
    rows = len(domain) + 1
    cols = len(brand) + 1

    matrix = [[0 for _ in range(cols)] for _ in range(rows)]

    for i in range(rows):
        matrix[i][0] = i
    for x in range(cols):
        matrix[0][x] = x
    #the algorithm starts at matrix[1][1] cell(1,1)
    for row in range(1, rows):
        for col in range(1, cols):
            if domain[row - 1] == brand[col -1]:
                matrix[row][col] = matrix[row - 1][col - 1]
            else: 
                matrix[row][col] = min(matrix[row][col - 1], 
                                       matrix[row - 1][col],
                                       matrix[row - 1][col - 1]) + 1
    return matrix[rows - 1][cols - 1]


def brandImpersonation(components):
    domain = components.get("domain")
    subdomain = components.get("subdomain")

    targets = [domain] + subdomain.split(".")

    for target in targets: 
        for brand in know_brands:
            if abs(len(target) - len(brand)) < 2:
                edit_distance = dp(target, brand)
                if 0 < edit_distance and edit_distance <= 2: 
                    return brand
    return None

def domain_entropy(components):
    domain = components.get("domain")
    ch_count = {}

    if not domain:
        return False
    for ch in domain: 
        ch_count[ch] = ch_count.get(ch, 0) + 1
    
    probability = {}
    char_len = len(domain)
    for ch, count in ch_count.items(): 
        probability[ch] = count / char_len

    entropy = 0
    for ch, prob in probability.items(): 
        entropy += -(prob) * math.log2(prob) #shannon entropy 

    if entropy > 3: 
        return True
    return False

def getDomainAge(components):
    domain = components.get("domain") + "." + components.get("top level domain")
    try:
        who = whois.whois(domain)
        creation_date = who.creation_date

        #check if a list 
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        #if empty 
        if creation_date is None:
            return None
        #UTC 
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        return age_days
    except Exception:
        return None


def finalVerdict(url, components):
    trigger = []
    score = 0

    signal_weight = {
        "brand_impersonation": 1.0,
        "ip_in_url" : 0.9,
        "unicode_url": 0.8,
        "suspicious_tld" : 0.75,
        "special_char_in_host": 0.7,
        "entropy_in_domain" : 0.6,
        "terms_in_hostname" : 0.5,
        "newly_registered_domain" : 0.45,
        "dots_in_hostname": 0.4,
        "long_hostname": 0.3,
        "excessive_slashes": 0.2
    }

    spoofed_brand = brandImpersonation(components)

    if spoofed_brand != None:
        trigger.append(f"brand_impersonation: {spoofed_brand}")
        score += signal_weight.get("brand_impersonation")
    
    if domain_entropy(components):
        trigger.append("entropy in domain")
        score += signal_weight.get("entropy_in_domain")

    if tld_check(components):
        trigger.append("suspicious tld")
        score += signal_weight.get("suspicious_tld")

    if unicodeURL(components):
        trigger.append("unicode_url")
        score += signal_weight.get("unicode_url")
    if IPinURL(components) == True:
        trigger.append("ip_in_url")
        score += signal_weight.get("ip_in_url")
    
    if specialCharacterInHost(components):
        trigger.append("special_char_in_host")
        score += signal_weight.get("special_char_in_host")

    if termsInHostname(components):
        trigger.append("terms_in_hostname")
        score += signal_weight.get("terms_in_hostname")

    if lengthOfHostDomain(components):
        trigger.append("long_hostname")
        score += signal_weight.get("long_hostname")

    if numberOfSlashes(url):
        trigger.append("excessive_slashes")
        score += signal_weight.get("excessive_slashes")

    if dotsHostname(components):
        trigger.append("dots_in_hostname")
        score += signal_weight.get("dots_in_hostname")

    
    age = getDomainAge(components)
    if age is not None and age < 180:
        trigger.append(f"new domain {age} days old")
        score += signal_weight.get("newly_registered_domain")


    if score >= HIGH_RISK_SCORE:
        level = "High Risk"
    elif score >= SUSPICIOUS_SCORE:
        level = "Suspicious"
    else:
        level = "Safe"

    return {
        "level": level,
        "score": score,
        "triggers": trigger,
        "age_days": age,
    }
    

        

if __name__ == "__main__":
    url = input("Enter URL: ")
    components = urlDissection(url)
    print(f"\nURL Components: {components}")
    print(f"Verdict: {finalVerdict(url, components)}")
    print(getDomainAge(components))





