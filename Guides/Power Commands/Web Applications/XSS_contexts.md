# XSS in Various Contexts

- INSIDE NORMAL HTML TAGS
    - `<p>{{injection}}</p>`
- DOUBLE QUOTED HTML TAG ATTRIBUTES
    - `<input type="text" value="{{injection}}">`
- SINGLE QUOTED HTML TAG ATTRIBUTES
    - `<input type="text" value='{{injection}}'>`
- UNQUOTED HTML TAG ATTRIBUTES
    - `<input type="text" value={{injection}}>`
- HTML COMMENTS
    - `<!-- {{injection}} -->`
- HTML EVENT HANDLERS
    - `<img src=x onerror="{{injection}}">`
- WITHIN SCRIPT TAGS
    - `<script>var x = "{{injection}}";</script>`
- URLS
    - `<a href="{{injection}}">click me</a>`