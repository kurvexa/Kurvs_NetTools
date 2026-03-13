// ---------------- Globals ----------------
let rawRDAP = null;      // store full RDAP JSON for WHOIS
let showingRaw = false;  // toggle state for raw WHOIS
let lastDetected = "";   // last detected cipher type

// ---------------- Speaker Icon Easter Egg ----------------
const speakerIcon = document.getElementById('speaker-icon');
const speakerAudio = document.getElementById('speaker-audio');

if (speakerIcon && speakerAudio) {
    speakerIcon.addEventListener('click', () => {
        // Start bounce
        speakerIcon.classList.add('bouncing');

        // Play audio
        speakerAudio.currentTime = 0;
        speakerAudio.play();

        // Stop bounce when audio ends
        speakerAudio.onended = () => {
            speakerIcon.classList.remove('bouncing');
        };
    });
}

// ---------------- WHOIS / RDAP ----------------
async function whoisLookup() {
    showingRaw = false;
    const toggleBtn = document.getElementById("toggleRawBtn");
    toggleBtn.innerText = "show raw data";

    try {
        let domain = document.getElementById("domain").value.trim();
        domain = domain.replace(/^https?:\/\//i, "").split("/")[0];

        if (!domain.includes(".")) {
            document.getElementById("outputWhois").innerText = "invalid domain format.";
            return;
        }

        let rdapResp = await fetch(`https://rdap.org/domain/${domain}`);
        if (!rdapResp.ok) throw new Error("domain not found or unsupported TLD");

        let data = await rdapResp.json();
        rawRDAP = data;

        let registrar = data.entities?.[0]?.vcardArray?.[1]?.[1]?.[3] || "Unknown";
        let created = data.events?.find(e => e.eventAction === "registration")?.eventDate || "Unknown";
        let expires = data.events?.find(e => e.eventAction === "expiration")?.eventDate || "Unknown";
        let nameservers = data.nameservers?.map(ns => ns.ldhName).join("\n") || "None";
        let abuseEmail = findAbuseEmail(data.entities || []);

        const output =
`Domain: ${data.ldhName}

Registrar: ${registrar}
Created: ${created}
Expires: ${expires}
Abuse Contact: ${abuseEmail}

Nameservers:
${nameservers}`;

        document.getElementById("outputWhois").innerText = output;

    } catch (error) {
        console.error(error);
        document.getElementById("outputWhois").innerText =
            "lookup failed. domain may be unregistered or RDAP server unavailable.";
    }
}

function findAbuseEmail(entities) {
    for (let entity of entities) {
        if (entity.roles && entity.roles.includes("abuse")) {
            let vcard = entity.vcardArray;

            if (vcard) {
                for (let field of vcard[1]) {
                    if (field[0] === "email") return field[3];
                }
            }
        }

        if (entity.entities) {
            let result = findAbuseEmail(entity.entities);
            if (result) return result;
        }
    }

    return "Not listed";
}

function toggleRaw() {
    if (!rawRDAP) return;

    const outputEl = document.getElementById("outputWhois");
    const btn = document.getElementById("toggleRawBtn");

    if (showingRaw) {
        whoisLookup();
        btn.innerText = "show raw data";
        showingRaw = false;
    } else {
        outputEl.innerText = JSON.stringify(rawRDAP, null, 2);
        btn.innerText = "show clean data";
        showingRaw = true;
    }
}

// ---------------- IP LOOKUP (MULTI PROVIDER FAILOVER) ----------------

const ipProviders = [
{
    name: "ipwhois.app",
    url: ip => `https://ipwhois.app/json/${ip}`,
    parse: data => 
`IP: ${data.ip}

Country: ${data.country}
Region: ${data.region}
City: ${data.city}

Latitude: ${data.latitude}
Longitude: ${data.longitude}

ISP: ${data.isp}
Organization: ${data.org}
ASN: ${data.asn}`
},

{
    name: "ip-api.com",
    url: ip => `http://ip-api.com/json/${ip}`,
    parse: data => 
`IP: ${data.query}

Country: ${data.country}
Region: ${data.regionName}
City: ${data.city}

Latitude: ${data.lat}
Longitude: ${data.lon}

ISP: ${data.isp}
Organization: ${data.org}
ASN: ${data.as}`
},

{
    name: "ipapi.co",
    url: ip => `https://ipapi.co/${ip}/json/`,
    parse: data =>
`IP: ${data.ip}

Country: ${data.country_name}
Region: ${data.region}
City: ${data.city}

Latitude: ${data.latitude}
Longitude: ${data.longitude}

ISP: ${data.org}`
}
];

async function ipLookup() {

    let ip = document.getElementById("ip").value.trim();
    let output = document.getElementById("outputIP");

    if (!ip) {
        output.innerText = "enter a valid IP";
        return;
    }

    for (let i = 0; i < ipProviders.length; i++) {

        let provider = ipProviders[i];

        try {

            output.innerText =
`Querying provider: ${provider.name}...`;

            let response = await fetch(provider.url(ip));

            if (response.status === 429) {
                throw new Error("RATE_LIMIT");
            }

            if (!response.ok) {
                throw new Error("API_ERROR");
            }

            let data = await response.json();

            output.innerText = provider.parse(data);
            return;

        } catch (err) {

            if (err.message === "RATE_LIMIT") {

                output.innerText =
` rate limit hit on ${provider.name}

switching to next provider...`;

            } else {

                output.innerText =
` ${provider.name} failed.

trying another provider...`;
            }

            await new Promise(r => setTimeout(r, 1200));
        }
    }

    output.innerText =
` all IP lookup providers failed or rate limits were exceeded.

try again later.`;
}

// ---------------- CIPHER DETECTION ----------------
function detectCipher() {
    const text = document.getElementById("cipher").value.trim();
    const out = document.getElementById("outputCipher");

    function isPrintable(str) {
        return /^[\x09\x0A\x0D\x20-\x7E]*$/.test(str);
    }

    // ---------- BASE64 ----------
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0) {
        try {
            const decoded = atob(text);
            if (isPrintable(decoded)) {
                lastDetected = "base64";
                out.innerText = "base64 detected";
                return;
            }
        } catch {}
    }

    // ---------- HEX ----------
    if (/^[0-9A-Fa-f]+$/.test(text) && text.length % 2 === 0) {
        try {
            let decoded = "";
            for (let i = 0; i < text.length; i += 2) {
                decoded += String.fromCharCode(parseInt(text.substr(i, 2), 16));
            }
            if (isPrintable(decoded)) {
                lastDetected = "hex";
                out.innerText = "hexadecimal detected";
                return;
            }
        } catch {}
    }

    // ---------- URL ENCODING ----------
    if (/%[0-9A-Fa-f]{2}/.test(text)) {
        try {
            const decoded = decodeURIComponent(text);
            if (isPrintable(decoded)) {
                lastDetected = "url";
                out.innerText = "url encoding detected";
                return;
            }
        } catch {}
    }

    // ---------- BINARY ----------
    if (/^[01\s]+$/.test(text)) {
        const parts = text.split(/\s+/).filter(Boolean);
        if (parts.length > 0 && parts.every(b => b.length === 8)) {
            try {
                const decoded = parts
                    .map(b => String.fromCharCode(parseInt(b, 2)))
                    .join("");
                if (isPrintable(decoded)) {
                    lastDetected = "binary";
                    out.innerText = "binary detected";
                    return;
                }
            } catch {}
        }
    }

    // ---------- ROT13 / CAESAR ----------
    if (/^[A-Za-z]+$/.test(text)) {
        lastDetected = "caesar";
        out.innerText = "caesar/ROT13 detected";
        return;
    }

    // ---------- UNKNOWN ----------
    lastDetected = "unknown";
    out.innerText = "cipher not recognized";
}

function decodeCipher() {
    let text = document.getElementById("cipher").value.trim();
    let result = "";

    if (lastDetected === "base64") {
        try {
            result = atob(text);
        } catch {
            result = "invalid base64 string";
        }

    } else if (lastDetected === "hex") {
        let str = "";
        for (let i = 0; i < text.length; i += 2) {
            str += String.fromCharCode(parseInt(text.substr(i, 2), 16));
        }
        result = str;

    } else if (lastDetected === "binary") {
        let str = "";
        text.split(/\s+/).filter(Boolean).forEach(b => {
            str += String.fromCharCode(parseInt(b, 2));
        });
        result = str;

    } else if (lastDetected === "caesar") {
        result = text.replace(/[A-Za-z]/g, c =>
            String.fromCharCode(
                c.charCodeAt(0) + (c.toUpperCase() <= 'M' ? 13 : -13)
            )
        );

    } else if (lastDetected === "url") {
        try {
            result = decodeURIComponent(text);
        } catch {
            result = "invalid url-encoded string";
        }

    } else {
        result = "unknown cipher";
    }

    document.getElementById("outputCipher").innerText = result;
}

// ---------------- IMAGE METADATA ----------------
function imageMetadata() {
    const input = document.getElementById("imageInput");
    const file = input.files[0];

    if (!file) return;

    EXIF.getData(file, function() {
        const allMeta = EXIF.getAllTags(this);

        if (allMeta.MakerNote && allMeta.MakerNote.length > 200) {
            allMeta.MakerNote = "[MakerNote too long, truncated]";
        }

        document.getElementById("outputImage").innerText =
            JSON.stringify(allMeta, null, 2);
    });
}
