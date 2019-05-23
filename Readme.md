# 0x0026
0x26 is the ASCII value for ampersand, which I'm told is derived from the stylistic ligature for `et`.  Given that this is a pretty brittle, low-level solution, I felt that this name was reasonably appropriate.  Either way, I'm not going to win any awards for my project names.

## Introduction
This project contacts the Etsy API and grabs all the listing for a predetermined list of stores.  It does a simple frequency analysis and returns the five most frequent words for each store.  Some of the stores it checks are pretty huge (in excess of 30 million words across descriptions), so give it a while.

This project does not:
 * Do proper XML, HTTP header, or JSON parsing.  Instead, it uses a brittle processing strategy.
 * Validate the returned data.  It does not disambiguate between:  feed done, invalid API key, API requests exhausted, invalid store, or invalid request.  You'll get junk data, but it won't tell you why.
 * Detect the pagination range or infer the current progress.  The processing strategy is greedy.
 * Worry too much about leaked memory from unfreed embedtls resources
 * Attempt to analyze text in any space other than ASCII (since Etsy returns escaped unicode, we could conceivably handle it, but we don't)
 * Provide an API key (you'll need your own!)
 
This project does:
 * Implement a simple word-frequency analysis in C

## Analysis
In implementing this, I learned that the Etsy REST endpoint returns data using two encoding strategies--content-length and chunked.  It seems that the endpoint will return chunked-encoded data for the first several paginations, then start producing data directly.  One possible interpretation is that the Etsy API needs to collect listing results from its own backend store and prepare them for transfer.  At the beginning of this process, the backend is responding to pagination requests on-demand and doesn't have the content lengths known ahead of time.  As it catches up, it's able to provide the client with prepared data .  This is consistent with the observation that the HTTP response latency is much lower when chunked encoding is not used by the response.

## Implementation details.
The Etsy REST endpoint rejects non-HTTPS traffic, so I had to throw in a TLS implementation.  The mbedtls initialization stuff was inspired by one of its authors' sample programs (ssl_client1.c), but it follows standard TLS initialization/handshake workflow.  The major gotcha is that I assume system root certificates come from OpenSSL (which is typical, although by no means *standard*), so I had to make the mbedtls initialization aware of the default root directory.  In a real solution, this would be an overridable default--if you're not using a Debian-based distro (such as Ubuntu), one fix would be to install OpenSSL from your package manager or symlink the CA dir to `/etc/ssl/certs`, the package can be removed afterward.

Before getting to the word histogram, preprocessing happens in a few steps after an HTTP request is submitted.
 * Response header is pulled from embedtls character-by-character to guarantee the buffer still contains the body (this does not involve the underlying socket--presumably embedls windows the TLS results)
 * Response header is processed for content-length or chunked encoding.  Response body is copied into a buffer accordingly.
 * Buffer is analyzed for the presence of top-level quoted "title" or "description".  If they exist, the matched, unescaped quotes immediately after are treated as bounding the text to analyze
 * Text is stripped of HTML/XML character entities, single-character words, non-alphanumeric characters, and control characters (not that there would be any in JSON, but there could be in HTTP data).
 * Resulting text is added into a histogram (trie) in lowercase form
 
## Why??
Yes, this would have taken a few minutes in Python.

However, I really wanted to understand the nuances of the endpoint, since a lot of the work I do involves low-level analysis of HTTP-mediated infrastructure.  Typically I'd come in with my own library for implementing (and snooping on server-side implementation details of) the TLS layer, so I wouldn't use something like mbedtls.  I certainly learned a lot.  Plus, how often do you get to roll your own trie?

## Attributions
mbedtls is the property of its authors, as per the included license.  I have modified the library by removing code I did not want to ship along with this project, but otherwise it is intact.
