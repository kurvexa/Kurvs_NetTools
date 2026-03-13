let rawRDAP = null; // store full RDAP data
let lastDetected = "";

// ---------------- RDAP / WHOIS LOOKUP ----------------
async function whoisLookup(){
    try{
        let domain = document.getElementById("domain").value.trim();
        let response = await fetch("https://rdap.org/domain/" + domain);
        let data = await response.json();

        rawRDAP = data;

        let registrar = data.entities?.[0]?.vcardArray?.[1]?.[1]?.[3] || "Unknown";
        let created = data.events.find(e => e.eventAction==="registration")?.eventDate || "Unknown";
        let expires = data.events.find(e => e.eventAction==="expiration")?.eventDate || "Unknown";
        let nameservers = data.nameservers.map(ns => ns.ldhName).join("\n");
        let abuseEmail = findAbuseEmail(data.entities || []);

        document.getElementById("output").innerText =
`Domain: ${data.ldhName}

Registrar: ${registrar}

Created: ${created}
Expires: ${expires}

Abuse Contact: ${abuseEmail}

Nameservers:
${nameservers}`;
    }
    catch(error){
        document.getElementById("output").innerText = "Lookup failed.";
    }
}

// recursive search for abuse emails
function findAbuseEmail(entities){
    for(let entity of entities){
        if(entity.roles && entity.roles.includes("abuse")){
            let vcard = entity.vcardArray;
            if(vcard){
                for(let field of vcard[1]){
                    if(field[0] === "email"){
                        return field[3];
                    }
                }
            }
        }
        if(entity.entities){
            let result = findAbuseEmail(entity.entities);
            if(result) return result;
        }
    }
    return "Not listed";
}

// ---------------- IP LOOKUP ----------------
async function ipLookup(){
    try{
        let ip = document.getElementById("ip").value;
        let response = await fetch("https://ipapi.co/" + ip + "/json/");
        let data = await response.json();
        document.getElementById("output").innerText = JSON.stringify(data,null,2);
    }
    catch(error){
        document.getElementById("output").innerText = "IP lookup failed.";
    }
}

// ---------------- CIPHER DETECTION ----------------
function detectCipher(){
    let text = document.getElementById("cipher").value.trim();

    if(/^[A-F0-9]+$/i.test(text)){
        lastDetected = "hex";
        document.getElementById("output").innerText = "Hexadecimal detected";
        return;
    }
    if(/^[01\s]+$/.test(text)){
        lastDetected = "binary";
        document.getElementById("output").innerText = "Binary detected";
        return;
    }
    if(/^[A-Za-z0-9+/=]+$/.test(text)){
        lastDetected = "base64";
        document.getElementById("output").innerText = "Base64 detected";
        return;
    }

    lastDetected = "unknown";
    document.getElementById("output").innerText = "Cipher not recognized";
}

// ---------------- CIPHER DECODING ----------------
function decodeCipher(){
    let text = document.getElementById("cipher").value.trim();
    let result = "";

    if(lastDetected === "base64"){
        try{
            result = atob(text);
        }
        catch{
            result = "Invalid Base64 string";
        }
    }
    else if(lastDetected === "hex"){
        let str = "";
        for(let i=0;i<text.length;i+=2){
            str += String.fromCharCode(parseInt(text.substr(i,2),16));
        }
        result = str;
    }
    else if(lastDetected === "binary"){
        let binary = text.split(" ");
        let str = "";
        binary.forEach(b => {
            str += String.fromCharCode(parseInt(b,2));
        });
        result = str;
    }
    else{
        result = "Unknown cipher";
    }

    document.getElementById("output").innerText = result;
}

// ---------------- SHOW RAW RDAP ----------------
function showRaw(){
    if(rawRDAP){
        document.getElementById("output").innerText = JSON.stringify(rawRDAP,null,2);
    }
}
