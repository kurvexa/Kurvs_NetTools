// ---------------- Globals ----------------
let rawRDAP = null;      // store full RDAP JSON for WHOIS
let showingRaw = false;  // toggle state for raw WHOIS
let lastDetected = "";   // last detected cipher type

// ---------------- WHOIS / RDAP ----------------
async function whoisLookup() {
    showingRaw = false;
    const toggleBtn = document.getElementById("toggleRawBtn");
    toggleBtn.innerText = "Show Raw Data";

    try {
        let domain = document.getElementById("domain").value.trim();
        domain = domain.replace(/^https?:\/\//i, "").split("/")[0]; // remove protocol/path

        if (!domain.includes(".")) {
            document.getElementById("outputWhois").innerText = "Invalid domain format.";
            return;
        }

        // Fetch from universal RDAP proxy
        let rdapResp = await fetch(`https://rdap.org/domain/${domain}`);
        if (!rdapResp.ok) throw new Error("Domain not found or unsupported TLD");
        let data = await rdapResp.json();
        rawRDAP = data;

        // Extract registrar, dates, nameservers
        let registrar = data.entities?.[0]?.vcardArray?.[1]?.[1]?.[3] || "Unknown";
        let created = data.events?.find(e => e.eventAction === "registration")?.eventDate || "Unknown";
        let expires = data.events?.find(e => e.eventAction === "expiration")?.eventDate || "Unknown";
        let nameservers = data.nameservers?.map(ns => ns.ldhName).join("\n") || "None";
        let abuseEmail = findAbuseEmail(data.entities || []);

        document.getElementById("outputWhois").innerText =
`Domain: ${data.ldhName}

Registrar: ${registrar}
Created: ${created}
Expires: ${expires}
Abuse Contact: ${abuseEmail}

Nameservers:
${nameservers}`;

    } catch (error) {
        console.error(error);
        document.getElementById("outputWhois").innerText =
            "Lookup failed. Domain may be unregistered or RDAP server unavailable.";
    }
}

// Recursive abuse email extraction
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

// Toggle raw / clean WHOIS display
function toggleRaw() {
    if (!rawRDAP) return;
    const outputEl = document.getElementById("outputWhois");
    const btn = document.getElementById("toggleRawBtn");

    if (showingRaw) {
        whoisLookup(); // restore clean view
        btn.innerText = "Show Raw Data";
        showingRaw = false;
    } else {
        outputEl.innerText = JSON.stringify(rawRDAP, null, 2);
        btn.innerText = "Show Clean Data";
        showingRaw = true;
    }
}

// ---------------- IP LOOKUP ----------------
async function ipLookup() {
    try {
        let ip = document.getElementById("ip").value.trim();
        if (!ip) { document.getElementById("outputIP").innerText = "Enter a valid IP"; return; }

        let response = await fetch(`https://api.allorigins.win/raw?url=${encodeURIComponent('https://ipapi.co/' + ip + '/json/')}`);
let data = await response.json();
        if (!response.ok) throw new Error("IP lookup failed");
        let data = await response.json();

        document.getElementById("outputIP").innerText = JSON.stringify(data, null, 2);
    } catch (error) {
        console.error(error);
        document.getElementById("outputIP").innerText = "IP lookup failed.";
    }
}

// ---------------- CIPHER DETECTION ----------------
function detectCipher() {
    let text = document.getElementById("cipher").value.trim();

    if (/^[A-F0-9]+$/i.test(text)) {
        lastDetected = "hex";
        document.getElementById("outputCipher").innerText = "Hexadecimal detected";
    } else if (/^[01\s]+$/.test(text)) {
        lastDetected = "binary";
        document.getElementById("outputCipher").innerText = "Binary detected";
    } else if (/^[A-Za-z0-9+/=]+$/i.test(text)) {
        lastDetected = "base64";
        document.getElementById("outputCipher").innerText = "Base64 detected";
    } else if (/^[A-Za-z]+$/i.test(text)) {
        lastDetected = "caesar";
        document.getElementById("outputCipher").innerText = "Caesar/ROT13 detected";
    } else if (/%[0-9A-Fa-f]{2}/.test(text)) {
        lastDetected = "url";
        document.getElementById("outputCipher").innerText = "URL encoding detected";
    } else {
        lastDetected = "unknown";
        document.getElementById("outputCipher").innerText = "Cipher not recognized";
    }
}

// ---------------- CIPHER DECODING ----------------
function decodeCipher() {
    let text = document.getElementById("cipher").value.trim();
    let result = "";

    if (lastDetected === "base64") {
        try { result = atob(text); } catch { result = "Invalid Base64 string"; }
    } else if (lastDetected === "hex") {
        let str = "";
        for (let i = 0; i < text.length; i += 2) {
            str += String.fromCharCode(parseInt(text.substr(i, 2), 16));
        }
        result = str;
    } else if (lastDetected === "binary") {
        let str = "";
        text.split(" ").forEach(b => { str += String.fromCharCode(parseInt(b, 2)); });
        result = str;
    } else if (lastDetected === "caesar") {
        result = text.replace(/[A-Za-z]/g, c =>
            String.fromCharCode(c.charCodeAt(0) + (c.toUpperCase() <= 'M' ? 13 : -13))
        );
    } else if (lastDetected === "url") {
        try { result = decodeURIComponent(text); } catch { result = "Invalid URL-encoded string"; }
    } else {
        result = "Unknown cipher";
    }

    document.getElementById("outputCipher").innerText = result;
}
