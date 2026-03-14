// ---------------- TRANSLATIONS & LANGUAGE ----------------

function setLanguage(lang){

  document.querySelectorAll("[data-i18n]").forEach(el=>{
    const key = el.getAttribute("data-i18n");
    const value = translations[lang]?.[key] || translations["en"]?.[key] || key;
    el.innerText = value;
  });

  document.querySelectorAll("[data-i18n-placeholder]").forEach(el=>{
    const key = el.getAttribute("data-i18n-placeholder");
    const value = translations[lang]?.[key] || translations["en"]?.[key] || key;
    el.placeholder = value;
  });

  localStorage.setItem("language", lang);

}

// ---------------- GLOBAL VARIABLES ----------------
let rawRDAP = null;
let showingRaw = false;
let lastDetected = "";

// ---------------- EVENT LISTENERS ON DOM CONTENT ----------------
document.addEventListener("DOMContentLoaded", () => {

  // Load language
  const browserLang = navigator.language.slice(0,2);
  const savedLang = localStorage.getItem("language") || (translations[browserLang] ? browserLang : "en");
  const langSelect = document.getElementById("languageSelect");
  if(langSelect) langSelect.value = savedLang;
  setLanguage(savedLang);

  // Enter key triggers
  enterTrigger("domain", whoisLookup);
  enterTrigger("dnsDomain", dnsLookup);
  enterTrigger("ip", ipLookup);

  // Speaker Easter Egg
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

// ---------------- ENTER KEY TRIGGER ----------------
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
  if(toggleBtn) toggleBtn.innerText = "show raw data";

  try{
    let domain = document.getElementById("domain").value.trim();
    domain = domain.replace(/^https?:\/\//i, "").split("/")[0];
    if(!domain.includes(".")){
      document.getElementById("outputWhois").innerText = "invalid domain format.";
      return;
    }

    const rdapResp = await fetch(`https://rdap.org/domain/${domain}`);
    if(!rdapResp.ok) throw new Error("domain not found");

    const data = await rdapResp.json();
    rawRDAP = data;

    const registrar = data.entities?.[0]?.vcardArray?.[1]?.[1]?.[3] || "Unknown";
    const created = data.events?.find(e => e.eventAction === "registration")?.eventDate || "Unknown";
    const expires = data.events?.find(e => e.eventAction === "expiration")?.eventDate || "Unknown";
    const nameservers = data.nameservers?.map(ns => ns.ldhName).join("\n") || "None";
    const abuseEmail = findAbuseEmail(data.entities || []);

    const output =
`Domain: ${data.ldhName}

Registrar: ${registrar}
Created: ${created}
Expires: ${expires}
Abuse Contact: ${abuseEmail}

Nameservers:
${nameservers}`;

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
        for(const field of vcard[1]){
          if(field[0] === "email") return field[3];
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

// ---------------- TOGGLE RAW RDAP ----------------
window.toggleRaw = function(){
  if(!rawRDAP) return;
  const outputEl = document.getElementById("outputWhois");
  const btn = document.getElementById("toggleRawBtn");

  if(showingRaw){
    whoisLookup();
    btn.innerText = "show raw data";
    showingRaw = false;
  } else {
    outputEl.innerText = JSON.stringify(rawRDAP,null,2);
    btn.innerText = "show clean data";
    showingRaw = true;
  }
}

// ---------------- DNS LOOKUP ----------------
window.dnsLookup = async function(){
  let domain = document.getElementById("dnsDomain").value.trim();
  const output = document.getElementById("outputDNS");
  domain = domain.replace(/^https?:\/\//i, "").split("/")[0];
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
    name:"ipwhois.app",
    url: ip=>`https://ipwhois.app/json/${ip}`,
    parse: data=>`IP: ${data.ip}\nCountry: ${data.country}\nRegion: ${data.region}\nCity: ${data.city}\nLatitude: ${data.latitude}\nLongitude: ${data.longitude}\nISP: ${data.isp}\nOrganization: ${data.org}\nASN: ${data.asn}`
  },
  {
    name:"freeipapi.com",
    url: ip=>`https://freeipapi.com/api/json/${ip}`,
    parse: data=>`IP: ${data.ipAddress}\nCountry: ${data.countryName}\nRegion: ${data.regionName}\nCity: ${data.cityName}\nLatitude: ${data.latitude}\nLongitude: ${data.longitude}\nISP: ${data.operatorName}`
  },
  {
    name:"ipapi.is",
    url: ip=>`https://api.ip-api.is/json/${ip}`,
    parse: data=>`IP: ${data.ip}\nCountry: ${data.location.country}\nRegion: ${data.location.state}\nCity: ${data.location.city}\nLatitude: ${data.location.latitude}\nLongitude: ${data.location.longitude}\nISP: ${data.asn.org}`
  },
  {
    name:"ipapi.co",
    url: ip=>`https://ipapi.co/${ip}/json/`,
    parse: data=>`IP: ${data.ip}\nCountry: ${data.country_name}\nRegion: ${data.region}\nCity: ${data.city}\nLatitude: ${data.latitude}\nLongitude: ${data.longitude}\nISP: ${data.org}`
  }
];

window.ipLookup = async function(){
  const ip = document.getElementById("ip").value.trim();
  const output = document.getElementById("outputIP");
  if(!ip){ output.innerText="enter a valid IP"; return; }

  for(const provider of ipProviders){
    try{
      output.innerText = `Querying ${provider.name}...`;
      const resp = await fetch(provider.url(ip));
      if(resp.status === 429) throw new Error("RATE_LIMIT");
      if(!resp.ok) throw new Error("API_ERROR");
      const data = await resp.json();
      output.innerText = provider.parse(data);
      return;
    }catch(err){
      output.innerText = `${provider.name} failed. trying another provider...`;
      await new Promise(r=>setTimeout(r,1200));
    }
  }
  output.innerText = "all IP lookup providers failed.";
}

// ---------------- CIPHER DETECTION ----------------
window.detectCipher = function(){
  const text = document.getElementById("cipher").value.trim();
  const out = document.getElementById("outputCipher");
  const printable = str => /^[\x09\x0A\x0D\x20-\x7E]*$/.test(str);

  if(/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length%4===0){
    try{ let decoded=atob(text); if(printable(decoded)){lastDetected="base64"; out.innerText="base64 detected"; return;} }catch{}
  }

  if(/^[0-9A-Fa-f]+$/.test(text) && text.length%2===0){
    let decoded=""; for(let i=0;i<text.length;i+=2) decoded+=String.fromCharCode(parseInt(text.substr(i,2),16));
    if(printable(decoded)){ lastDetected="hex"; out.innerText="hex detected"; return; }
  }

  if(/%[0-9A-Fa-f]{2}/.test(text)){
    try{ let decoded=decodeURIComponent(text); if(printable(decoded)){ lastDetected="url"; out.innerText="url encoding detected"; return; } }catch{}
  }

  if(/^[01\s]+$/.test(text)){
    const parts=text.split(/\s+/).filter(Boolean);
    if(parts.every(b=>b.length===8)){
      const decoded=parts.map(b=>String.fromCharCode(parseInt(b,2))).join("");
      if(printable(decoded)){ lastDetected="binary"; out.innerText="binary detected"; return; }
    }
  }

  if(/^[A-Za-z]+$/.test(text)){ lastDetected="caesar"; out.innerText="caesar/rot detected"; return; }

  lastDetected="unknown"; out.innerText="cipher not recognized";
}

// ---------------- CAESAR DECODER ----------------
function caesarDecode(text){
  const printable = str => /^[\x09\x0A\x0D\x20-\x7E]*$/.test(str);
  for(let shift=1; shift<26; shift++){
    let decoded="";
    for(let c of text){
      if(c>='A' && c<='Z') decoded=decoded+String.fromCharCode((c.charCodeAt(0)-65+26-shift)%26+65);
      else if(c>='a' && c<='z') decoded=decoded+String.fromCharCode((c.charCodeAt(0)-97+26-shift)%26+97);
      else decoded+=c;
    }
    if(printable(decoded)) return decoded+`  (shift ${shift})`;
  }
  return "unknown Caesar shift";
}

// ---------------- DECODE ----------------
window.decodeCipher=function(){
  const text=document.getElementById("cipher").value.trim();
  let result="";
  if(lastDetected==="base64"){ try{result=atob(text);}catch{result="invalid base64";} }
  else if(lastDetected==="hex"){ for(let i=0;i<text.length;i+=2) result+=String.fromCharCode(parseInt(text.substr(i,2),16)); }
  else if(lastDetected==="binary"){ text.split(/\s+/).filter(Boolean).forEach(b=>result+=String.fromCharCode(parseInt(b,2))); }
  else if(lastDetected==="caesar"){ result=caesarDecode(text); }
  else if(lastDetected==="url"){ try{result=decodeURIComponent(text);}catch{result="invalid url encoding";} }
  else result="unknown cipher";
  document.getElementById("outputCipher").innerText=result;
}

// ---------------- IMAGE METADATA ----------------
window.imageMetadata = function(){
  const input = document.getElementById("imageInput");
  if(!input.files[0]) return;
  EXIF.getData(input.files[0], function(){
    let allMeta=EXIF.getAllTags(this);
    if(allMeta.MakerNote && allMeta.MakerNote.length>200) allMeta.MakerNote="[MakerNote truncated]";
    document.getElementById("outputImage").innerText=JSON.stringify(allMeta,null,2);
  });
}
