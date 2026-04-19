// Replacement for the setLanguage function
function setLanguage(lang) {
    // Standard safety check instead of translations[lang]?.
    var langData = translations[lang];
    if (!langData) langData = translations["en"];

    document.querySelectorAll("[data-i18n]").forEach(function(el) {
        var key = el.getAttribute("data-i18n");
        // Standard check instead of langData?.[key]
        var value = (langData && langData[key]) ? langData[key] : key;
        el.innerText = value;
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach(function(el) {
        var key = el.getAttribute("data-i18n-placeholder");
        var value = (langData && langData[key]) ? langData[key] : key;
        el.placeholder = value;
    });

    localStorage.setItem("language", lang);
}

// ---------------- GLOBAL VARIABLES ----------------
let rawRDAP = null;
let showingRaw = false;
let lastDetected = "";

// ---------------- EVENT LISTENERS ----------------
document.addEventListener("DOMContentLoaded", () => {
  const browserLang = navigator.language.slice(0,2);
  const savedLang = localStorage.getItem("language") || (translations[browserLang] ? browserLang : "en");
  const langSelect = document.getElementById("languageSelect");
  if(langSelect) langSelect.value = savedLang;
  setLanguage(savedLang);

  enterTrigger("domain", whoisLookup);
  enterTrigger("dnsDomain", dnsLookup);
  enterTrigger("ip", ipLookup);

  const speakerIcon = document.getElementById('speaker-icon');
  const speakerAudio = document.getElementById('speaker-audio');
  if(speakerIcon && speakerAudio){
    speakerIcon.addEventListener('click', () => {
      speakerIcon.classList.add('bouncing');
      speakerAudio.currentTime = 0;
      speakerAudio.play();
      speakerAudio.onended = () => speakerIcon.classList.remove('bouncing');
    });
  }
});

function enterTrigger(id, func){
  const el = document.getElementById(id);
  if(!el) return;
  el.addEventListener("keypress", e=>{
    if(e.key === "Enter"){ e.preventDefault(); func(); }
  });
}

// ---------------- WHOIS / RDAP ----------------
window.whoisLookup = async function() {
  showingRaw = false;
  const toggleBtn = document.getElementById("toggleRawBtn");
  if(toggleBtn) toggleBtn.innerText = translations[localStorage.getItem("language")]?.raw || "show raw data";

  try{
    let domain = document.getElementById("domain").value.trim();
    domain = domain.replace(/^https?:\/\//i, "").split("/");
    if(!domain.includes(".")){
      document.getElementById("outputWhois").innerText = "invalid domain format.";
      return;
    }

    const rdapResp = await fetch(`https://rdap.org/domain/${domain}`);
    if(!rdapResp.ok) throw new Error("domain not found");

    const data = await rdapResp.json();
    rawRDAP = data;
// might not work WIP
    var registrar = "Unknown";
if (data.entities && data.entities && data.entities.vcardArray) {
    registrar = data.entities.vcardArray || "Unknown";
}
// might not work WIP
    const created = data.events?.find(e => e.eventAction === "registration")?.eventDate || "Unknown";
    const expires = data.events?.find(e => e.eventAction === "expiration")?.eventDate || "Unknown";
    const nameservers = data.nameservers?.map(ns => ns.ldhName).join("\n") || "None";
    const abuseEmail = findAbuseEmail(data.entities || []);

    const output = `Domain: ${data.ldhName}\n\nRegistrar: ${registrar}\nCreated: ${created}\nExpires: ${expires}\nAbuse Contact: ${abuseEmail}\n\nNameservers:\n${nameservers}`;
    document.getElementById("outputWhois").innerText = output;

  }catch(error){
    document.getElementById("outputWhois").innerText = "lookup failed. domain may be unregistered.";
  }
}

function findAbuseEmail(entities){
  for(const entity of entities){
    if(entity.roles && entity.roles.includes("abuse")){
      const vcard = entity.vcardArray;
      if(vcard){
        for(const field of vcard){
          if(field === "email") return field;
        }
      }
    }
    if(entity.entities){
      const result = findAbuseEmail(entity.entities);
      if(result) return result;
    }
  }
  return "Not listed";
}

window.toggleRaw = function(){
  if(!rawRDAP) return;
  const outputEl = document.getElementById("outputWhois");
  const btn = document.getElementById("toggleRawBtn");
  const lang = localStorage.getItem("language");

  if(showingRaw){
    whoisLookup();
    btn.innerText = translations[lang]?.raw || "show raw data";
    showingRaw = false;
  } else {
    outputEl.innerText = JSON.stringify(rawRDAP,null,2);
    btn.innerText = translations[lang]?.clean || "show clean data";
    showingRaw = true;
  }
}

// ---------------- DNS LOOKUP ----------------
window.dnsLookup = async function(){
  let domain = document.getElementById("dnsDomain").value.trim();
  const output = document.getElementById("outputDNS");
  domain = domain.replace(/^https?:\/\//i, "").split("/");
  if(!domain.includes(".")){ output.innerText = "invalid domain."; return; }

  const recordTypes = {A:1,AAAA:28,MX:15,NS:2,TXT:16,CNAME:5};
  let results = `DOMAIN: ${domain}\n\n`;

  try{
    for(const [name,type] of Object.entries(recordTypes)){
      const resp = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
      const data = await resp.json();
      if(data.Answer){
        results += `[${name}]\n`;
        data.Answer.forEach(r=> results += `${r.data}\n`);
        results += "\n";
      }
    }
    if(results === `DOMAIN: ${domain}\n\n`) results += "no DNS records found.";
    output.innerText = results;
  }catch(err){
    output.innerText = "DNS lookup failed.";
  }
}

// ---------------- IP LOOKUP ----------------
const ipProviders = [
  {
    name: "ipapi.co",
    url: ip => `https://ipapi.co/${ip}/json/`,
    parse: d => ({
      source: "ipapi.co",
      ip: d.ip,
      country: d.country_name,
      region: d.region,
      city: d.city,
      isp: d.org,
      asn: d.asn
    })
  },
  {
    name: "ipinfo.io",
    url: ip => `https://ipinfo.io/${ip}/json?token=69cc5e234f44b1`,
    parse: d => ({
      source: "ipinfo.io",
      ip: d.ip,
      country: d.country,
      region: d.region,
      city: d.city,
      isp: d.org,
      asn: d.asn
    })
  },
  {
    name: "geojs.io",
    url: ip => `https://get.geojs.io/v1/ip/geo/${ip}.json`,
    parse: d => ({
      source: "geojs.io",
      ip: d.ip,
      country: d.country,
      region: d.region,
      city: d.city,
      isp: d.organization_name,
      asn: d.asn
    })
  },
  {
    name: "geoplugin.net",
    url: ip => `https://www.geoplugin.net/json.gp?ip=${ip}`,
    parse: d => ({
      source: "geoplugin.net",
      ip: d.geoplugin_request,
      country: d.geoplugin_countryName,
      region: d.geoplugin_region,
      city: d.geoplugin_city,
      isp: null,
      asn: null
    })
  },

  //  will likely fail in browser cus of cors
  {
    name: "ipwhois.app",
    url: ip => `https://ipwhois.app/json/${ip}`,
    parse: d => ({
      source: "ipwhois.app",
      ip: d.ip,
      country: d.country,
      region: d.region,
      city: d.city,
      isp: d.isp,
      asn: d.asn
    })
  },
  {
    name: "freeipapi.com",
    url: ip => `https://freeipapi.com/api/json/${ip}`,
    parse: d => ({
      source: "freeipapi.com",
      ip: d.ipAddress,
      country: d.countryName,
      region: d.regionName,
      city: d.cityName,
      isp: d.operatorName,
      asn: d.asn
    })
  }
];

window.ipLookup = async function () {
  const ip = document.getElementById("ip").value.trim();
  const output = document.getElementById("outputIP");

  if (!ip) {
    output.innerText = "enter a valid IP";
    return;
  }

  for (const provider of ipProviders) {
    try {
      output.innerText = `Querying ${provider.name}...`;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);

      const resp = await fetch(provider.url(ip), {
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!resp.ok) throw new Error();

      const data = await resp.json();
      const parsed = provider.parse(data);

      output.innerText =
        `Source: ${parsed.source}\n` +
        `IP: ${parsed.ip}\n` +
        `Country: ${parsed.country}\n` +
        `Region: ${parsed.region}\n` +
        `City: ${parsed.city}\n` +
        `ISP: ${parsed.isp || "N/A"}\n` +
        `ASN: ${parsed.asn || "N/A"}`;

      return;

    } catch (err) {
      output.innerText = `${provider.name} failed. trying another...`;
      await new Promise(r => setTimeout(r, 300));
    }
  }

  output.innerText = "all IP lookup providers failed.";
};

// ---------------- CIPHER DETECTION ----------------
window.detectCipher = function(){
  const text = document.getElementById("cipher").value.trim();
  const out = document.getElementById("outputCipher");
  const printable = str => /^[\x09\x0A\x0D\x20-\x7E]*$/.test(str);
  
  // Logic Fix: Avoid false positives on plain English
  const commonWords = /\b(the|and|this|that|with|from|have|they|would|there|what)\b/i;
  if(commonWords.test(text)) {
      lastDetected = "none";
      out.innerText = "Plaintext detected (contains common words, may be inaccurate. WIP, please contact original artist (@kurvexa) if wrong)";
      return;
  }

  if(/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0 && text.length > 4){
    try{ let decoded=atob(text); if(printable(decoded)){lastDetected="base64"; out.innerText="base64 detected"; return;} }catch{}
  }

  if(/^[0-9A-Fa-f]+$/.test(text) && text.length % 2 === 0 && text.length > 4){
    lastDetected="hex"; out.innerText="hex detected"; return;
  }

  if(/%[0-9A-Fa-f]{2}/.test(text)){
    lastDetected="url"; out.innerText="url encoding detected"; return;
  }

  if(/^[01\s]+$/.test(text) && text.length > 7){
    lastDetected="binary"; out.innerText="binary detected"; return;
  }

  if(/^[A-Za-z\s.,!?]+$/.test(text) && text.length > 3){ 
      lastDetected="caesar"; out.innerText="caesar/rot detected"; return; 
  }

  lastDetected="unknown"; out.innerText="cipher not recognized";
}

function caesarDecode(text){
  let results = "";
  for(let shift=1; shift<26; shift++){
    let decoded="";
    for(let c of text){
      if(c>='A' && c<='Z') decoded+=String.fromCharCode((c.charCodeAt(0)-65+26-shift)%26+65);
      else if(c>='a' && c<='z') decoded+=String.fromCharCode((c.charCodeAt(0)-97+26-shift)%26+97);
      else decoded+=c;
    }
    // Only show shifts that look like English
    if(/\b(the|and|is|at|of|to|in)\b/i.test(decoded)){
        return decoded + ` (Shift ${shift})`;
    }
    results = "No common English words found in any shift.";
  }
  return results;
}

window.decodeCipher=function(){
  const text=document.getElementById("cipher").value.trim();
  let result="";
  if(lastDetected==="base64"){ try{result=atob(text);}catch{result="invalid base64";} }
  else if(lastDetected==="hex"){ for(let i=0;i<text.length;i+=2) result+=String.fromCharCode(parseInt(text.substr(i,2),16)); }
  else if(lastDetected==="binary"){ text.split(/\s+/).filter(Boolean).forEach(b=>result+=String.fromCharCode(parseInt(b,2))); }
  else if(lastDetected==="caesar"){ result=caesarDecode(text); }
  else if(lastDetected==="url"){ try{result=decodeURIComponent(text);}catch{result="invalid url encoding";} }
  else result="unknown cipher or plaintext";
  document.getElementById("outputCipher").innerText=result;
}

// ---------------- IMAGE METADATA ----------------
window.imageMetadata = function(){
  const input = document.getElementById("imageInput");
  if(!input.files) return;
  EXIF.getData(input.files, function(){
    let allMeta=EXIF.getAllTags(this);
    if(allMeta.MakerNote && allMeta.MakerNote.length>200) allMeta.MakerNote="[MakerNote truncated]";
    document.getElementById("outputImage").innerText=JSON.stringify(allMeta,null,2);
  });
}
