## Browser signatures database

Each .yaml contains the signatures of a different browser.

Each signature refers to the browser's behavior upon browsing to a site
not cached or visited before.

Each signature contains:
* The parameters in the TLS client hello message.
* The HTTP/2 HEADERS frame sent by the browser.
* The HTTP/2 SETTINGS frame sent by the browser.
