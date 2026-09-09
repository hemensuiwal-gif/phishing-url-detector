# Phishing URL Detector Website

A standalone browser version of the Phishing URL Detector. It uses the same visual design, validation, scoring rules, and transparent result breakdown as the Flask app, but runs entirely in the browser.

## Run

Open `index.html` directly in a browser, or serve the folder locally:

```powershell
py -m http.server 8000
```

Then open <http://127.0.0.1:8000>.

The analyzer only parses the submitted URL locally. It does not visit the destination, follow redirects, or collect credentials.
