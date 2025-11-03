# Javascript Deobfuscation

Obfuscation is a technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view, though performance may be slower. This is usually achieved automatically by using an obfuscation tool, which takes code as an input, and attempts to re-write the code in a way that is much more difficult to read, depending on its design.

```bash
curl http:/SERVER_IP:PORT/	#cURL GET request
curl -s http:/SERVER_IP:PORT/ -X POST	#cURL POST request
curl -s http:/SERVER_IP:PORT/ -X POST -d "param1=sample"	#cURL POST request with data
echo hackthebox | base64	#base64 encode
echo ENCODED_B64 | base64 -d	#base64 decode
echo hackthebox | xxd -p	#hex encode
echo ENCODED_HEX | xxd -p -r	#hex decode
echo hackthebox | tr 'A-Za-z' 'N-ZA-Mn-za-m'	#rot13 encode
echo ENCODED_ROT13 | tr 'A-Za-z' 'N-ZA-Mn-za-m'	#rot13 decode
```

![](https://academy.hackthebox.com/storage/modules/41/obfuscation_example.jpg)

`It must be noted that doing authentication or encryption on the client-side is not recommended, as code is more prone to attacks this way.`

## **Deobfuscation Websites**

https://matthewfl.com/unPacker.html (Ensure you do not leave any empty lines before the script, as it may affect the deobfuscation process and give inaccurate results.)

https://obfuscator.io/

https://jsfuck.com/

[JS Console](https://jsconsole.com/)

[Prettier](https://prettier.io/playground/)

[Beautifier](https://beautifier.io/)

[JSNice](http://www.jsnice.org/)

https://www.toptal.com/developers/javascript-minifier

## Basic Obfuscation

Code obfuscation is usually not done manually, as there are many tools for various languages that do automated code obfuscation. Many online tools can be found to do so, though many malicious actors and professional developers develop their own obfuscation tools to make it more difficult to deobfuscate.

for example:

```bash
function log() {
 console.log('HTB JavaScript Deobfuscation Module');
}
# minified
function log(){console.log("HTB JavaScript Deobfuscation Module")}
```

Many tools can help us minify JavaScript code, like [javascript-minifier](https://javascript-minifier.com/). We simply copy our code, and click `Minify.`

Now, let us obfuscate our line of code to make it more obscure and difficult to read. First, we will try [BeautifyTools](http://beautifytools.com/javascript-obfuscator.php) to obfuscate our code:

```bash
function log(){console.log("HTB JavaScript Deobfuscation Module")}
# obfuscation
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('2 0(){1.0("3 5 4 6")}',7,7,'log|console|function|HTB|Deobfuscation|JavaScript|Module'.split('|'),0,{}))
```

The above type of obfuscation is known as "packing", which is usually recognizable from the six function arguments used in the initial function "function(p,a,c,k,e,d)".

A `packer` obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the `(p,a,c,k,e,d)` function to re-build the original code during execution. The `(p,a,c,k,e,d)` can be different from one packer to another. However, it usually contains a certain order in which the words and symbols of the original code were packed to know how to order them during execution.

## Advanced Obfuscation

```bash
function log(){console.log("HTB JavaScript Deobfuscation Module")}

##

function _0xfd1d(){var _0x35a507=['otGXmdqWr3P1Dujx','ovjhBvzuAG','n2D2CNrnua','nfLrEhjUDa','mZe5uNboAwro','nJu5nJeXmfbtyMfcuW','mZy1nZK1og9fAvLtDq','Bg9N','mtq5nZKYou15BfrqvW','mtKZnZq2me1LrhjRzG','nJi0nJq0ofbODM1ftq','sfrciePHDMfty3jPChqGrgvVyMz1C2nHDgLVBIbnB2r1Bgu','mJeZnJmWmfv2Afb4va'];_0xfd1d=function(){return _0x35a507;};return _0xfd1d();}(function(_0xcfecb1,_0x29a9b9){var _0x1a1b04=_0x1944,_0x22050c=_0xcfecb1();while(!![]){try{var _0x2bc04=parseInt(_0x1a1b04(0x187))/0x1+-parseInt(_0x1a1b04(0x185))/0x2+-parseInt(_0x1a1b04(0x17e))/0x3+parseInt(_0x1a1b04(0x182))/0x4*(-parseInt(_0x1a1b04(0x184))/0x5)+parseInt(_0x1a1b04(0x188))/0x6*(-parseInt(_0x1a1b04(0x181))/0x7)+parseInt(_0x1a1b04(0x189))/0x8*(parseInt(_0x1a1b04(0x180))/0x9)+parseInt(_0x1a1b04(0x17f))/0xa*(parseInt(_0x1a1b04(0x183))/0xb);if(_0x2bc04===_0x29a9b9)break;else _0x22050c['push'](_0x22050c['shift']());}catch(_0x208fc7){_0x22050c['push'](_0x22050c['shift']());}}}(_0xfd1d,0xe59fc));function _0x1944(_0x5a0ae8,_0x552144){var _0xfd1d1=_0xfd1d();return _0x1944=function(_0x1944fa,_0x1fbf43){_0x1944fa=_0x1944fa-0x17d;var _0x550ea4=_0xfd1d1[_0x1944fa];if(_0x1944['koqfFO']===undefined){var _0x2a6d79=function(_0x591141){var _0x55a7e5='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';var _0x15482d='',_0x1da3a1='';for(var _0xe402ec=0x0,_0x2780fa,_0x437aae,_0x1e306f=0x0;_0x437aae=_0x591141['charAt'](_0x1e306f++);~_0x437aae&&(_0x2780fa=_0xe402ec%0x4?_0x2780fa*0x40+_0x437aae:_0x437aae,_0xe402ec++%0x4)?_0x15482d+=String['fromCharCode'](0xff&_0x2780fa>>(-0x2*_0xe402ec&0x6)):0x0){_0x437aae=_0x55a7e5['indexOf'](_0x437aae);}for(var _0x35340c=0x0,_0xb8c1d5=_0x15482d['length'];_0x35340c<_0xb8c1d5;_0x35340c++){_0x1da3a1+='%'+('00'+_0x15482d['charCodeAt'](_0x35340c)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x1da3a1);};_0x1944['jQsTVN']=_0x2a6d79,_0x5a0ae8=arguments,_0x1944['koqfFO']=!![];}var _0x24f318=_0xfd1d1[0x0],_0x241edd=_0x1944fa+_0x24f318,_0x1a6722=_0x5a0ae8[_0x241edd];return!_0x1a6722?(_0x550ea4=_0x1944['jQsTVN'](_0x550ea4),_0x5a0ae8[_0x241edd]=_0x550ea4):_0x550ea4=_0x1a6722,_0x550ea4;},_0x1944(_0x5a0ae8,_0x552144);}function log(){var _0x4d14ef=_0x1944;console[_0x4d14ef(0x186)](_0x4d14ef(0x17d));}
```

## Deobfuscation examples

```bash
'use strict';
function generateSerial() {
  ...SNIP...
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
};
```

Basically sending an empty POST  request to `/serial.php` 

We can try and curl and sent a POST request to it :

```bash
┌──(darksidedani㉿darkside)-[~]
└─$ curl -s http://94.237.60.32:36071/serial.php -X POST     
N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz  
```

Tip: We add the "-s" flag to reduce cluttering the response with unnecessary data

However, `POST` request usually contains `POST` data. To send data, we can use the "`-d "param1=sample"`" 

We seem to receive an encoded message?

Common encoding methods:

- `base64`
- `hex`
- `rot13`

```bash
echo N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz | base64 -d 
7h15_15_a_s3cr37_m3554g3
# we can use it again to send it back a POST to the server
curl -s http://94.237.60.32:36071/serial.php -X POST -d "serial=7h15_15_a_s3cr37_m3554g3"
HTB{ju57_4n07h3r_r4nd0m_53r14l}
```