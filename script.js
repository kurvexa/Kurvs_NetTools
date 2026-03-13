let rawRDAP = null;   // store full RDAP data
let showingRaw = false; // for WHOIS toggle
let lastDetected = ""; // for cipher detection

// ---------------- WHOIS / RDAP ----------------
async function whoisLookup() {
    showingRaw = false; // reset toggle
    document.getElementById("toggleRawBtn").innerText = "Show Raw Data";

    try {
        // 1️⃣ Get domain and clean input
        let domain = document.getElementById("domain").value.trim();
        domain = domain.replace(/^https?:\/\//i, "").split("/")[0]; // remove protocol & path

        // 2️⃣ Basic validation
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
            document.getElementById("outputWhois").innerText = "Invalid domain format.";
            return;
        }

        // 3️⃣ Extract TLD
        let domainParts = domain.split(".");
        let tld = domainParts[domainParts.length - 1].toLowerCase();

        // 4️⃣ Fetch IANA bootstrap JSON
        let bootstrapResp = await fetch("https://data.iana.org/rdap/dns.json");
        let bootstrap = await bootstrapResp.json();

        let tldData = bootstrap.tlds[tld];
        if (!tldData) {
            document.getElementById("outputWhois").innerText =
                `No RDAP data available for TLD: .${tld}\nTry IP lookup or check the domain manually.`;
            return;
        }

        if (!tldData.services || tldData.services.length === 0) {
            document.getElementById("outputWhois").innerText =
                `No RDAP server listed for TLD: .${tld}\nTry IP lookup or check the domain manually.`;
            return;
        }

        // 5️⃣ Fetch domain info from RDAP server
        let server = tldData.services[0][0];
        let rdapResp = await fetch(`${server}/domain/${domain}`);
        if (!rdapResp.ok) throw new Error("Domain not found or RDAP server returned error");
        let data = await rdapResp.json();

        rawRDAP = data;

        // 6️⃣ Extract useful info safely
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
            "Lookup failed. This domain may not be registered, TLD unsupported, or RDAP server unavailable.";
    }
}

// Recursive search for abuse emails
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

// Toggle raw / clean WHOIS data
function toggleRaw() {
    if (!rawRDAP) return;
    const outputEl = document.getElementById("outputWhois");
    const btn = document.getElementById("toggleRawBtn");

    if (showingRaw) {
        whoisLookup();
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
        let ip = document.getElementById("ip").value;
        let response = await fetch("https://ipapi.co/" + ip + "/json/");
        let data = await response.json();
        document.getElementById("outputIP").innerText = JSON.stringify(data, null, 2);
    } catch (error) {
        document.getElementById("outputIP").innerText = "IP lookup failed.";
    }
}

// ---------------- CIPHER DETECTION ----------------
function detectCipher() {
    let text = document.getElementById("cipher").value.trim();

    if (/^[A-F0-9]+$/i.test(text)) {
        lastDetected = "hex";
        document.getElementById("outputCipher").innerText = "Hexadecimal detected";
        return;
    }
    if (/^[01\s]+$/.test(text)) {
        lastDetected = "binary";
        document.getElementById("outputCipher").innerText = "Binary detected";
        return;
    }
    if (/^[A-Za-z0-9+/=]+$/i.test(text)) {
        lastDetected = "base64";
        document.getElementById("outputCipher").innerText = "Base64 detected";
        return;
    }
    if (/^[A-Za-z]+$/i.test(text)) {
        lastDetected = "caesar";
        document.getElementById("outputCipher").innerText = "Caesar/ROT13 detected";
        return;
    }
    if (/%[0-9A-Fa-f]{2}/.test(text)) {
        lastDetected = "url";
        document.getElementById("outputCipher").innerText = "URL encoding detected";
        return;
    }

    lastDetected = "unknown";
    document.getElementById("outputCipher").innerText = "Cipher not recognized";
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
