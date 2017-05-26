
// Base level of iterations when generating encryption key
var encIts = 9753;

// Internal global vars
var saltthepass = SaltThePass;
var encryptingNow = false;

function validateEmail(val) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(val);
}

function cryptOverlay(switchon, msg)
{
	if (switchon)
	{
		document.getElementById('overlaymsg').innerHTML = msg;
		document.getElementById('overlay').style.display = 'table';
	}
	else
	{
		document.getElementById('overlay').style.display = 'none';
	}
}

var lastSysMsg = '';
function doSysMsg(msg)
{
	lastSysMsg = msg;
	try {
		var s = document.getElementById('sysmsgs');
		var d = new Date();
		var date = d.getFullYear()+'-'+pad(d.getMonth(),2)+'-'+pad(d.getDate(),2)+' '+pad(d.getHours(),2)+':'+pad(d.getMinutes(),2)+':'+pad(d.getSeconds(),2);
		s.innerHTML = date + ' ' + msg + '<br />\n' + s.innerHTML;
	} catch (err) {}
}

function cryptOverlayOff()
{
	cryptOverlay(false);
}

function pad(num, size)
{ 
	return ('000000000' + num).substr(-size); 
}

var md5 = function(value) {
    return CryptoJS.MD5(value).toString();
}

var ripemd160 = function(value) {
    return CryptoJS.RIPEMD160(value).toString();	
}

var sha256 = function(value) {
    return CryptoJS.SHA256(value).toString();	
}

var sha512 = function(value) {
    return CryptoJS.SHA512(value).toString();	
}

var sha3 = function(value) {
    return CryptoJS.SHA3(value).toString();	
}

var hmacsha3 = function(value) {
    return CryptoJS.HmacSHA3(value).toString();	
}


function aeDecrypt(data, pass, user)
{
	decry = '';
	try {
	// 1. Let's get the salt
  	salt = data.substring(0,32);
  	data = data.substring(32,data.length);

  	// 2. Let's make a decent pass and iv from their u and p
	pi = getPBKDF2PS(pass, user, salt);

	// 3. Decrypt with these values then
	cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: CryptoJS.enc.Hex.parse(data)});
	var decrypted = CryptoJS.AES.decrypt(cipherParams, CryptoJS.enc.Hex.parse(pi['pass']), { iv: CryptoJS.enc.Hex.parse(pi['iv']), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });

	decry = decrypted.toString(CryptoJS.enc.Utf8);
	} catch (err) {}
	return decry;	
}

function aeCrypt(data, pass, user)
{
	// this is crypt only, not hmac. it guarantees confidentiality
	// but not integrity. As such it's a little quicker and produces
	// smaller output than a full encrypt+mac
	encry = '';
	try {
	// 1. Let's make a salt
  	salt = CryptoJS.lib.WordArray.random(16).toString();
  	
  	// 2. Let's make a decent pass and iv from their u and p
	pi = getPBKDF2PS(pass, user, salt);
	
	// 3. Encrypt with these values then
	var encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(data), CryptoJS.enc.Hex.parse(pi['pass']), { iv: CryptoJS.enc.Hex.parse(pi['iv']), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
 });
	encry = salt+encrypted.ciphertext;
	} catch (err) {}
	return encry;
}

function getPBKDF2PS(pass, user, salt)
{
	pass = strToHexPad(pass + salt, 1024);
	user = strToHexPad(user, 256);
	its  = 1000;
	pbkd = CryptoJS.PBKDF2(CryptoJS.enc.Hex.parse(pass), CryptoJS.enc.Hex.parse(user), { keySize: 256/32, iterations: its, hasher:CryptoJS.algo.SHA256 });
	// split result into the _actual_ pass and salt for the encryption
	pbkd = pbkd.toString();
	var pi = [];
	pi['pass'] = strPad(pbkd.substring(0,pbkd.length/2),64);
	pi['iv']   = strPad(pbkd.substring(pbkd.length/2, pbkd.length),32);
	return pi;
}

function strPad(val, length)
{
	if (val.length>length) { val = val.substring(0,length); }
	if (val.length<length) 
	{
		while (val.length<length)
		{
			val = val + '0';
		}
		val = val.substring(0,length);
	}
	return val;	
}


function strToHexPad(val, length)
{
	val = toHex(val);
	if (val.length>length) { val = val.substring(0,length); }
	if (val.length<length) 
	{
		while(val.length<length)
		{
			val = val + '0';
		}
		val = val.substring(0,length);
	}
	return val;
}

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex.toLowerCase();
}

function getAESkey(salt)
{
	var sp = document.getElementById('sp').value;
	var its     = encIts + getMpItMod(sp);
	var encpp   = CryptoJS.PBKDF2(sp, salt, { keySize: 512/32, iterations: its });
	return encpp.toString();
}

function getMpItMod(mp)
{
  var sum = 0;
  mp.split('').forEach(function(alphabet) {
      sum += alphabet.charCodeAt(0) - 64;
  });
  return sum;
}

function getKeKm(salt)
{
  var kekm   = {ke:'',km:''};
  var encpp  = getAESkey(theusername+salt);
  var ke     = encpp.substring(0,encpp.length/2);
  var km     = encpp.substring(encpp.length/2,encpp.length);
  kekm['ke'] = CryptoJS.enc.Base64.parse(ke);
  kekm['km'] = CryptoJS.enc.Base64.parse(km);
  return kekm;
}

function encryptAndMac(message)
{
  err = 'unknown error';
  try {
    var ivl = 22; 

    // generate a random iv
    var rnd     = CryptoJS.lib.WordArray.random(16).toString();
    var ivs     = saltthepass.saltthepass('sha3', rnd, '', '').substring(0,ivl);
    var iv      = CryptoJS.enc.Base64.parse(ivs);

    // get the keys (passing the iv additionally as a salt modifier)
    var kekm = getKeKm(ivs);
   
    // encrypt this.
    var encrypted = CryptoJS.AES.encrypt(message, kekm['ke'], {
    			iv: iv,
			    mode: CryptoJS.mode.CBC, 
    			padding: CryptoJS.pad.Pkcs7
    		});

    //Calculate HMAC of iv + encrypted...
    var HMAC = CryptoJS.HmacSHA256(ivs+encrypted.toString(), kekm['km']);

    // Final encrypted concatenation...
    return ivs + encrypted.toString() + HMAC.toString();
  } catch (err) {
	alert('Encryption failed '+err);
  }
  return '';
}

function decryptMacAnd(message)
{
  try {
    var ivl = 22;
    var hml = 64;

    // determine the iv
    var ivs = message.substring(0,ivl);
    var iv      = CryptoJS.enc.Base64.parse(ivs);

    // get the keys (passing the iv additionally as a salt modifier)
    var kekm = getKeKm(ivs);

    // strip and keep the hmac off the end
    var hmac = message.substring(message.length-hml, message.length);
    var message = message.substring(ivl,message.length-hml);

    //Calculate HMAC of iv + encrypted...
    var HMAC = CryptoJS.HmacSHA256(ivs+message, kekm['km']);

    if (hmac == HMAC.toString())
    {
      // continue to decrypt the message then!
      decrypted = CryptoJS.AES.decrypt(message, kekm['ke'], {
      		iv: iv,
		    mode: CryptoJS.mode.CBC, 
			padding: CryptoJS.pad.Pkcs7
      	});
      decrypted = decrypted.toString(CryptoJS.enc.Utf8);

	  return decrypted;  
    }
    else
    {
      throw 'HMAC verification failed.';
    }
  }
  catch (err) { doSysMsg(err); }
  return '';
}

var passphrase = document.getElementById('sp');
var snote      = document.getElementById('snote');
var decrypt    = document.getElementById('decry');
var encrypt    = document.getElementById('encry');
var overlay    = document.getElementById('overlay');
var enc        = snote.value;

passphrase.addEventListener('keyup', vChange);
passphrase.addEventListener('keypress', passKeyPress);
overlay.addEventListener('click', noClick);

decrypt.addEventListener('click', doDecrypt);
encrypt.addEventListener('click', doEncrypt);

function noClick(e)
{
    if (!e)
      e = window.event;

    //IE9 & Other Browsers
    if (e.stopPropagation) {
      e.stopPropagation();
    }
    //IE8 and Lower
    else {
      e.cancelBubble = true;
    }
}

function vChange()
{
	if (pvalid())
	{
		decrypt.className = '';
		encrypt.className = '';
	}
	else
	{
		decrypt.className = 'btndisabled';
		encrypt.className = 'btndisabled';
	}
}

function passKeyPress(event)
{
    if (event.which == 13 || event.keyCode == 13) {
        doDecrypt();
        return false;
    }
    return true;
};

function pvalid()
{
	if ((passphrase.value.length > 0) && (!encryptingNow))
	{
		return true;
	}
	else
	{
		return false;
	}
}

var doDecryptTimeout;
function doDecrypt()
{
	if (pvalid())
	{
		encryptingNow = true;
		cryptOverlay(true,'Decrypting...');
		theusername = passphrase.value;
		try { clearTimeout(doDecryptTimeout); } catch (err) {}
		doDecryptTimeout = setTimeout(doDecryptGo, 250);		
	}
	return false;
}

var scto;
function doDecryptGo()
{
	decrypted = decryptMacAnd(snote.value);
	if (decrypted.length==0)
	{
		enc = snote.value;
		snote.value = 'Decryption failed. Incorrect passphrase.';
		clearTimeout(scto);
		scto = setTimeout(showCrypted, 1500);
	}
	else
	{
		enc = decrypted;
		scto = setTimeout(showCrypted, 250);
	}
}

function doEncrypt()
{
	if (pvalid())
	{
		encryptingNow = true;
		cryptOverlay(true,'Encrypting...');
		theusername = passphrase.value;
		try { clearTimeout(doDecryptTimeout); } catch (err) {}
		doDecryptTimeout = setTimeout(doEncryptGo, 250);		
	}
	return false;
}

function doEncryptGo()
{
	var encrypted = encryptAndMac(snote.value);
	if (encrypted.length==0)
	{
		enc = snote.value;
		snote.value = 'Encryption failed.';
		clearTimeout(scto);
		scto = setTimeout(showCrypted, 1500);
	}
	else
	{
		enc = encrypted;
		scto = setTimeout(showCrypted, 250);
	}
}

function showCrypted()
{
	snote.value = enc;
	encryptingNow = false;
	cryptOverlay(false,'Decrypting...');
}

function validateEmail(val) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(val);
}

function flash(ele, sstart, ssend, duration)
{
	ele.style = sstart;
	setTimeout(duration, endflash(ele,ssend));
}

function endflash(ele,ssend)
{
	ele.style = ssend;
}

function flashClass(elename, cstart, cend, duration)
{
	document.getElementById(elename).className = cstart;
	//ef = "endFlash('"+elename+"','"+cend+"')";
	setTimeout(function(){
			endFlash(elename,cend);
		},duration);
}

function endFlash(elename,cend)
{
	document.getElementById(elename).className = cend;
}

function tvee(elename)
{
	ele = document.getElementById(elename);
	if (ele)
	{
		try 
		{
			if (ele.style.display == 'block' || ele.style.display == '')
			{
			  ele.style.display = 'none';
		   	}
		   	else
		   	{
 			  see(elename);
			}
		}
		catch (err)
		{

		}
	}
}

var eases = new Array();

function he(ele) 
{
   try { document.getElementById(ele).style.display = 'none'; eases[ele] = 0; } catch(err) { }
}

function see(ele) 
{
	// Show element with easing
	try 
	{ 
		obj = document.getElementById(ele);
		if (obj)
		{
			if (obj.style.display != '')
			{
				// Make it transparent
				setOpacity(obj,0);
				// Show it though
				obj.style.display = '';
				eases[ele] = 0;
				setTimeout(function(){seet(ele);},10);
			}
			else
			{
			}
		}
		else
		{

		}
	} 
	catch(err) 
	{
	}
}

function seet(ele)
{
	try
	{
		eases[ele] += 2;
		obj = document.getElementById(ele);
		if (obj)
		{
			setOpacity(obj, eases[ele]);
			if (eases[ele] < 100)
			{
				setTimeout(function(){seet(ele);},10);
			}
		}
		else
		{
		}
	}
	catch (err)
	{
	}
}

function setOpacity(obj, opacity)
{
	obj.style.filter = "alpha(opacity=" + opacity + ")"; // For IE filter to work, obj MUST have layout
	obj.style.KHTMLOpacity = opacity / 100; // Safari and Konqueror
	obj.style.MozOpacity = opacity / 100; // Old Mozilla and Firefox
	obj.style.opacity = opacity / 100; // CSS3 opacity for browsers that support it
}
