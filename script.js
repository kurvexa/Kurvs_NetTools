let lastDetected = "";

async function whoisLookup(){

let domain = document.getElementById("domain").value;

let response = await fetch(
"https://api.ipwhois.io/domain?domain=" + domain
);

let data = await response.json();

document.getElementById("output").innerText =
JSON.stringify(data,null,2);

}

async function ipLookup(){

let ip = document.getElementById("ip").value;

let response = await fetch(
"http://ip-api.com/json/" + ip
);

let data = await response.json();

document.getElementById("output").innerText =
JSON.stringify(data,null,2);

}

function detectCipher(){

let text = document.getElementById("cipher").value.trim();

if(/^[A-F0-9]+$/i.test(text)){
lastDetected = "hex";
document.getElementById("output").innerText="Hexadecimal detected";
return;
}

if(/^[01\s]+$/.test(text)){
lastDetected = "binary";
document.getElementById("output").innerText="Binary detected";
return;
}

if(/^[A-Za-z0-9+/=]+$/.test(text)){
lastDetected = "base64";
document.getElementById("output").innerText="Base64 detected";
return;
}

lastDetected="unknown";

document.getElementById("output").innerText="Cipher not recognized";

}

function decodeCipher(){

let text = document.getElementById("cipher").value.trim();

let result="";

if(lastDetected=="base64"){

result = atob(text);

}

else if(lastDetected=="hex"){

let str='';

for(let i=0;i<text.length;i+=2){

str += String.fromCharCode(
parseInt(text.substr(i,2),16)
);

}

result = str;

}

else if(lastDetected=="binary"){

let binary = text.split(" ");

let str="";

binary.forEach(b=>{
str += String.fromCharCode(parseInt(b,2));
});

result = str;

}

else{

result="Unknown cipher";

}

document.getElementById("output").innerText=result;

}
