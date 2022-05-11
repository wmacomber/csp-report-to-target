# csp-report-to-target

This app was created because I was curious about the Content-Security-Policy header and wanted to see CSP reporting in action.

This app acts as a simple endpoint for Content-Security-Policy reporting.  It (in a very basic way) parses an incoming CSP violation notification and displays it to the server console.  Run it somewhere, point your web server's CSP reporting directives towards it (instructions for configuring nginx headers below), and watch the server console for the violations.  Firefox appears to immediately send all violations in  separate requests, where Blink-based browsers send groups of items in a single request (I tested Edge and  Chrome) tend to send some violations immediately but wait to send other ones (I haven't looked into why).

# nginx setup
Let's say we have a location block:

```
    location / {
        try_files $uri $uri/ =404;
    }
```

We want to use the Content-Security-Policy header to add to our defense-in-depth approach to security.  First step would be to add the CSP header itself, along with a semi-restrictive default-src policy.  So now our location block will look more like this:

```
    location / {
        try_files $uri $uri/ =404;
        add_header Content-Security-Policy "default-src 'self';";
    }
```

We can force nginx to send this header back with every response regardless of response code if we add "always" at the end:

```
    location / {
        try_files $uri $uri/ =404;
        add_header Content-Security-Policy "default-src 'self';" always;
    }
```

There are several different directives for the CSP header: default-src, script-src, and style-src are just some of them - https://content-security-policy.com/ has a list and a reference.

Now to the purpose of this very basic server: to catch CSP reports.  Catching them is pretty easy, the data is sent from the browser via a simple HTTPS (it will not work over HTTP) POST request.  The browser gets the posting URL from the Content-Security-Policy header that's sent from the server.  Since browser compatibility is something we need to concern ourselves with**, we need to add an additional header: Report-To.  This is set to a JSON string containing endpoint information.  Make your JSON using proper conventions and insert it between two apostrophes.  The location block should look like this now:

```
    location / {
        try_files $uri $uri/ =404;
        add_header Report-To '{"group": "csp-test", "max_age": 10886400, "endpoints": [{ "url": "https://your.site/csp-report-to-target/report-to"}]}';
        add_header Content-Security-Policy "default-src 'self';" always;
    }
```

The "group" is what's referred to in the report-to directive.  Let's not forget to implement it in the 
CSP add_header line:

```
    location / {
        try_files $uri $uri/ =404;
        add_header Report-To '{"group": "csp-test", "max_age": 10886400, "endpoints": [{ "url": "https://your.site/csp-report-to-target/report-to"}]}';
        add_header Content-Security-Policy "default-src 'self'; report-uri https://your.site/csp-report-to-target/report-uri; report-to csp-test;" always;
    }
```

Note we included *both* report-uri *and* report-to in the Content-Security-Policy header.  That's for compatibility.  Remember that the "Report-To" header is necessary to make the CSP "report-to" directive work properly.

** Firefox doesn't know how to handle CSP's "report-to" directive, instead looking for the "report-uri" directive.  Firefox also uses a different data format and Content-Type (application/csp-report) than the  link-based browsers do (application/reports+json), but that only really matters on the report-receiving application side.

## Sample Application Console Output
(I'd bet anyone who ever finds this repo on purpose is looking for what's in this section)

```
csp-report-to-target listening on port 3002
==========
--- Gecko Firefox (application/csp-report) POST - /report-uri:
OUTPUT:
{
  timestamp: 1652229387725,
  'blocked-uri': 'https://fonts.googleapis.com/css2?family=Exo+2:wght@700&display=swap',
  'line-number': undefined,
  'column-number': undefined,
  'document-uri': 'https://web.site/test.html',
  'source-file': undefined,
  'violated-directive': 'default-src',
  'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report-uri",
  message: 'Violation of default-src. Problem(s) in https://web.site/test.html. Blocked URI is https://fonts.googleapis.com/css2?family=Exo+2:wght@700&display=swap.'
}
==========
--- Gecko Firefox (application/csp-report) POST - /report-uri:
OUTPUT:
{
  timestamp: 1652229387753,
  'blocked-uri': 'inline',
  'line-number': 9,
  'column-number': 1,
  'document-uri': 'https://web.site/test.html',
  'source-file': 'https://web.site/test.html',
  'violated-directive': 'default-src',
  'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report-uri",
  message: 'Violation of default-src. Problem(s) in https://web.site/test.html. Line 9, column 1.'
}
```

```
==========
--- Blink Edge (application/reports+json) POST - /report-to:
OUTPUT:
{
  timestamp: 1652229489876,
  items: [
    {
      'blocked-uri': 'https://fonts.googleapis.com/css2?family=Exo+2:wght@700&display=swap',
      'line-number': 7,
      'column-number': undefined,
      'document-uri': 'https://web.site/test.html',
      'source-file': 'https://web.site/test.html',
      'violated-directive': 'style-src-elem',
      'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report; report-to csp-test;",
      'actual-timestamp': 1652229489876,
      message: 'Violation of style-src-elem. Problem(s) in https://web.site/test.html. Blocked URI is https://fonts.googleapis.com/css2?family=Exo+2:wght@700&display=swap.'
    }
  ]
}
==========
--- Blink Edge (application/reports+json) POST - /report-to:
OUTPUT:
{
  timestamp: 1652229549801,
  items: [
    {
      'blocked-uri': 'inline',
      'line-number': 37,
      'column-number': undefined,
      'document-uri': 'https://web.site/test.html',
      'source-file': 'https://web.site/test.html',
      'violated-directive': 'script-src-elem',
      'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report; report-to csp-test;",
      'actual-timestamp': 1652229489830,
      message: 'Violation of script-src-elem. Problem(s) in https://web.site/test.html. Line 37.'
    },
    {
      'blocked-uri': 'inline',
      'line-number': 9,
      'column-number': undefined,
      'document-uri': 'https://web.site/test.html',
      'source-file': 'https://web.site/test.html',
      'violated-directive': 'style-src-elem',
      'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report; report-to csp-test;",
      'actual-timestamp': 1652229489798,
      message: 'Violation of style-src-elem. Problem(s) in https://web.site/test.html. Line 9.'
    }
  ]
}
```

```
==========
--- Blink Chrome (application/reports+json) POST - /report-to:
OUTPUT:
{
  timestamp: 1652229690116,
  items: [
    {
      'blocked-uri': 'https://fonts.googleapis.com/css2?family=Exo+2:wght@700&display=swap',
      'line-number': 7,
      'column-number': undefined,
      'document-uri': 'https://web.site/test.html',
      'source-file': 'https://web.site/test.html',
      'violated-directive': 'style-src-elem',
      'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report-uri; report-to csp-test;",
      'actual-timestamp': 1652229690116,
      message: 'Violation of style-src-elem. Problem(s) in https://web.site/test.html. Blocked URI is https://fonts.googleapis.com/css2?family=Exo+2:wght@700&display=swap.'
    }
  ]
}
==========
--- Blink Chrome (application/reports+json) POST - /report-to:
OUTPUT:
{
  timestamp: 1652229750062,
  items: [
    {
      'blocked-uri': 'inline',
      'line-number': 37,
      'column-number': undefined,
      'document-uri': 'https://web.site/test.html',
      'source-file': 'https://web.site/test.html',
      'violated-directive': 'script-src-elem',
      'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report-uri; report-to csp-test;",
      'actual-timestamp': 1652229690084,
      message: 'Violation of script-src-elem. Problem(s) in https://web.site/test.html. Line 37.'
    },
    {
      'blocked-uri': 'inline',
      'line-number': 9,
      'column-number': undefined,
      'document-uri': 'https://web.site/test.html',
      'source-file': 'https://web.site/test.html',
      'violated-directive': 'style-src-elem',
      'original-policy': "default-src 'self'; report-uri https://web.site/csp-report-to-target/report-uri; report-to csp-test;",
      'actual-timestamp': 1652229690060,
      message: 'Violation of style-src-elem. Problem(s) in https://web.site/test.html. Line 9.'
    }
  ]
}
```
