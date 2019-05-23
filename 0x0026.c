#include <mbedtls/config.h>
#include <mbedtls/platform.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>

#include <string.h>
#include <ctype.h>


/*---------------------------------------------------------------------------*\
|                                System Helpers                               |
\*---------------------------------------------------------------------------*/
size_t expand(char** dst, size_t sz_old) {
  size_t sz_new = 2*sz_old;                 // The new size is double the old
  char* ret = calloc(1, sz_new);
  if(!ret) return 0;                        // realloc failure?
  memcpy(ret, *dst, sz_old);                // copy over
  free(*dst);                               // get rid of old region
  *dst = ret;                               // update pointer in caller
  return sz_new;
}


/*---------------------------------------------------------------------------*\
|                                    EZTrie                                   |
\*---------------------------------------------------------------------------*/
// This is a stupid simple implementation of a trie-based histogram, with
// blacklisted words.  I cooked this up specifically for this exercise, so I
// make no guarantess of its general applicability.
// I could save a lot of space by making some sane observations about ASCII
// (e.g., a word won't contain non-printing characters, which saves about 256
// bytes per node), but we ignore those optimizations here.
// Blacklist from Wikipedia's list of the 100 most common English words
#define WBL_LEN (100)
const uint64_t BLACKLIST = (uint64_t)(~0);
char* WordBlacklist[] = {
"the","be","to","of","and","a","in","that","have","I","it","for","not","on",
"with","he","as","you","do","at","this","but","his","by","from","they","we",
"say","her","she","or","an","will","my","one","all","would","there","their",
"what","so","up","out","if","about","who","get","which","go","me","when","make",
"can","like","time","no","just","him","know","take","people","into","year",
"your","good","some","could","them","see","other","than","then","now","look",
"only","come","its","over","think","also","back","after","use","two","how",
"our","work","first","well","way","even","new","want","because","any","these",
"give","day","most","us"};

typedef struct TrieNode {
    uint64_t           count;
    unsigned char      character;
    struct TrieNode*   parent;
    struct TrieNode*   children[256];
} TrieNode;

typedef struct EZTrie {
    TrieNode*   children[256];
    TrieNode**  winners;
    uint8_t     sz_winners;
} EZTrie;

TrieNode* EZTrieFind(EZTrie* trie, char* word) {
  char c;
  TrieNode** nodes = (TrieNode**)trie->children;
  TrieNode*  ret = NULL;
  while(*word) {
    c = tolower(*(word++));
    if(NULL == nodes[c]) {
      // If NULL, have to allocate it
      nodes[c] = calloc(1, sizeof(TrieNode));
      nodes[c]->parent = ret;
      nodes[c]->character = c;
    }
    ret   = nodes[c];
    nodes = ret->children;
  }
  return ret;
}

uint64_t EZTrieSet(EZTrie* trie, char* word, uint64_t val) {
  TrieNode* node = EZTrieFind(trie, word);
  if((~0) == node->count)
    return 0;
  node->count += val;
  return node->count;
}

uint64_t EZTrieGet(EZTrie* trie, char* word) {
  TrieNode* node = EZTrieFind(trie, word);
  return BLACKLIST == node->count ? 0 : node->count;
}

void EZTrieInit(EZTrie* trie, uint8_t sz_winners) {
  for(int i=0; i<WBL_LEN; i++)
    EZTrieSet(trie, WordBlacklist[i], BLACKLIST);

  trie->sz_winners = sz_winners;
  trie->winners = calloc(sz_winners, sizeof(TrieNode*));
}

uint64_t EZTrieInc(EZTrie* trie, char* word) {
  uint64_t val = BLACKLIST;
  TrieNode* node = EZTrieFind(trie, word);
  TrieNode* winner;
  if(BLACKLIST == node->count)
    return 0;
  node->count++;
  val = node->count;

  // If our node is already a winner, stop
  for(int i=0; i<trie->sz_winners; i++)
    if(trie->winners[i] == node)
      return val;

  // Slide down the list, reorganizing if needed
  for(int i=trie->sz_winners-1; i>=0; i--) {
    winner = trie->winners[i];
    if(NULL==node) break;  // we don't need to reposition null nodes
    if(NULL==winner || BLACKLIST==winner->count || node->count>winner->count) {
      trie->winners[i] = node;
      node = winner;
    }
  }
  return val;
}

void TrieNodeFree(TrieNode* node) {
  for(int i=0; i<256; i++)
    if(node->children[i])
      TrieNodeFree(node->children[i]);
  free(node);
}

void EZTrieFree(EZTrie* trie) {
  for(int i=0; i<256; i++)
    if(trie->children[i])
      TrieNodeFree(trie->children[i]);

  free(trie->winners);
}

char* NodeToWord(TrieNode* node) {
  // NOTE:  must be freed by caller (now if we had used a radix tree...)
  uint32_t len = 0;
  char* ret;
  TrieNode* p = node;

  // We should never get a null input, but we might as well handle that case,
  // since that will make testing easier.
  if(!node)
    return NULL;

  // Backtrack up to the root to get the length
  while(p->parent) {
    len++;
    p = p->parent;
  }

  // Prepare the return
  ret = calloc(1,2+len); // actual length is one more, plus include null
  while(node->parent) {
    ret[len--] = node->character;
    node = node->parent;
  }
  ret[len--] = node->character;    // Lastly, get parent character
  return ret;
}


/*---------------------------------------------------------------------------*\
|                            Word Frequency Helpers                           |
\*---------------------------------------------------------------------------*/
char* JSONSections[] = {"title", "description"};
char* JSONTextGet(char* p) {
  // Detects the next valid JSONSection, returning a pointer to the top of the
  // entry body (after the leading '"').  Replaces the trailing '"' with '\0'.
  // If no entry can be detected, returns NULL.  Assume p NULL-terminated.
  char* q;

  // Find opening quote and ensure the entry type matches a desired JSONSection
  // This will break horribly (strncmp overflow on p) if the data is malformed.
  char breakout = 0;
  while(*p && !breakout) {
    if('"' == p[0] && '\\' != p[-1]) { // Find opening quote
      for(int i=0; i<2; i++) {
        if(!strncmp(p+1, JSONSections[i], strlen(JSONSections[i]))) {
          p += 2 + strlen(JSONSections[i]); // navigate after closing '"'
          breakout = 1;
          break;
        }
      }
    }
    p++;
  }

  // Now bracket the text (after ':') and convert matching unescaped '"' to null
  while(*p) { // if p was null before, this is skipped
    if('"' != p[0] || '\\' == p[-1]) continue; // p needs to land on quote
    q=p+1;
    while(*q) {
      if('"' == q[0] && '\\' != q[-1]) {
        // Found it!
        q[0] = 0;
        return p+1;
      }
      q++;
    }
    p++;
  }

  // If we didn't escape by now, we didn't find anything.
  return NULL;
}

void JSONTextClean(char* p) {
  while(*p) {
    // Ignore letters and digits
    if(isalnum(*p)) {
      p++; // do nothing
    } else if('\\' == p[0]) {
      p[0] = p[1] = ' ';
      p += 2;
    }else if('&' == p[0]) {
      // Detect XML and HTML character entities.  Coarsely, this is any char
      // between unescaped & and ;, but we'd need to parse because this is
      // dependent on definition within the DTD.  Still, ours is a fine
      // approximation
      char* q = p+1;
      while(*q && ';' != *q) {
        // Make sure the sequence is correct.  If not, only convert leading &
        if(!isalnum(*q) && '#' != *q) {*p=' '; break;}
        q++;
      }
      while(p!=q) {*p = ' '; p++;} // convert all to spaces
      *p=' ';p++;
    } else if(ispunct(*p) || isspace(*p) || iscntrl(*p)) {
      // Finally, whatever is left should probably be converted to whitespace,
      // but we'll be cautious and check a few overlapping macros.
      *p = ' ';
      p++;
    }
  }
}

#define NSPACE(p) while(*p && ' ' != *p) p++;  // move p to next space char
#define NGLYPH(p) while(*p && ' ' == *p) p++;  // move p to next non-space char

int JSONTextToHistogram(char* p, EZTrie* trie) {
  char c=0,*q = p;
  int count = 0;
  while(*p && *q) {
    q=p; NSPACE(q);                            // move q to next space after p
    if(q-p<2) {p=q; NGLYPH(p); q=p; continue;} // skip empty spaces, singletons
    c = *q; *q = 0;      // save and null to tokenize
    EZTrieInc(trie, p);
    count++;             // keep track of number of words
    *q = c;              // restore
    p=q; NGLYPH(p);                            // move p to next glyph after q
  }

  return count;
}


/*---------------------------------------------------------------------------*\
|                                     HTTP                                    |
\*---------------------------------------------------------------------------*/
#define SERVER_PORT "443"                // Default HTTPS port
#define SERVER_NAME "openapi.etsy.com"   // Application default endpoint
#define BUF_LEN (1024)         // initial copy buffer from HTTPS
mbedtls_x509_crt cacert = {0}; // Holds global cert configuration.

typedef struct EtsyFreqReq{
  mbedtls_net_context   fd;     // FD to server
  mbedtls_ssl_context   ssl;    // used to send/recv
  mbedtls_ssl_config    conf;   // configuration parameters for SSL
  char*                 store;  // null-terminated store name
  char*                 key;    // null-terminated API key
  uint32_t              offset; // which page to check
  uint32_t              limit;  // max number of items per page
  EZTrie                hist;   // word frequency histogram
} EtsyFreqReq;

void LibInit() {
  int ret = 1;

  // Load certificates
  mbedtls_x509_crt_init( &cacert );
  ret = mbedtls_x509_crt_parse_path( &cacert, "/etc/ssl/certs");
  ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
  if( ret < 0 ) {
    mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
  }
}

int EtsyFreqReqInit(EtsyFreqReq* req, char* server, char* port) {
  int ret = -1, flags = -1;
  mbedtls_net_init( &req->fd );
  mbedtls_ssl_init( &req->ssl );
  mbedtls_ssl_config_init( &req->conf );

  // Crypto RNG init
  static const char *pers = "0x0026";
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init( &ctr_drbg );
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers) );

  // SSL init
  if(0 != (ret = mbedtls_ssl_config_defaults( &req->conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_STREAM,
                   MBEDTLS_SSL_PRESET_DEFAULT))) ;

  mbedtls_ssl_conf_authmode( &req->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
  mbedtls_ssl_conf_ca_chain( &req->conf, &cacert, NULL );
  mbedtls_ssl_conf_rng( &req->conf, mbedtls_ctr_drbg_random, &ctr_drbg );

  if(0 != (ret=mbedtls_ssl_setup(&req->ssl, &req->conf))) {
    mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
  }

  if(0 != (ret=mbedtls_ssl_set_hostname(&req->ssl, SERVER_NAME))) {
    mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
  }

  // Connect to server
  if(0 != (ret=mbedtls_net_connect(&req->fd, server, port, MBEDTLS_NET_PROTO_TCP)));
  mbedtls_ssl_set_bio( &req->ssl, &req->fd, mbedtls_net_send, mbedtls_net_recv, NULL );

  // Perform SSL handshake
  while(0 != (ret=mbedtls_ssl_handshake(&req->ssl))) {
    if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
      mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
      exit(1);
    }
  }

  // Verify server certificate
  if(0 != (flags=mbedtls_ssl_get_verify_result(&req->ssl))) {
    char vrfy_buf[512];
    mbedtls_printf( " failed\n" );
    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
    mbedtls_printf( "%s\n", vrfy_buf );
  }
  return 0;
}

void EtsyFreqReqFree(EtsyFreqReq* req) {
  // There is some additional mbedtls cleanup we can and should do, but we
  // don't do it.

  EZTrieFree(&req->hist);               // clear underlying trie
  mbedtls_ssl_close_notify(&req->ssl);  // hangup
}

const char get_fmt[] =
  "GET /v2/shops/%s/listings/active?"
    "api_key=%s&"
    "fields=title,description&"
    "limit=%u&"
    "offset=%u "
  "HTTP/1.1\r\n"
  "Host: openapi.etsy.com\r\n\r\n";
char EtsyFreqReqSend(EtsyFreqReq* req) {
  int ret = -1;
  int len = strlen(get_fmt) +
            strlen(req->key) +
            strlen(req->store) + 10;  // 10 is a limit/offset fudge factor
  char* get_str = calloc(1, len+1);
  len = sprintf(get_str, get_fmt, req->store, req->key, req->limit, req->offset);
  while(0>=(ret = mbedtls_ssl_write( &req->ssl, get_str, len))) {
    if( MBEDTLS_ERR_SSL_WANT_READ  != ret &&
        MBEDTLS_ERR_SSL_WANT_WRITE != ret) {
      return -1;
    }
  }
  free(get_str);
  return 0;
}


#define NNEWL(p) while(*p && '\n' != *p) p++;  // move p to next newline
#define NCOLN(p) while(*p && ':' != *p) p++;  // move p to next colon
char ChunkedLine[] = "Transfer-Encoding: chunked";
char SizedLine[]   = "Content-Length";
int HeaderGetEncoding(char* hdr) {
  // Process the HTTP header until we find:
  //  * Content-Length (return value)
  //  * Transfer-Encoding: chunked (return -1)
  // We utterly cop out here and just do a strncmp against static strings.  In
  // a more robust solution, we'd take lowercase and strip whitespace and all
  // that (HTTP headers are not case-sensitive in the RFC).
  char* p = hdr;
  while(*p) {
    if(!strncmp(p, ChunkedLine, strlen(ChunkedLine)))
      return -1;
    if(!strncmp(p, SizedLine,   strlen(SizedLine))) {
      NCOLN(p); p++;
      return strtol(p, NULL, 10);
    }
    NNEWL(p); p++;
  }

  return -1; // if nothing, assume chunked encoding
}

long HeaderRip(EtsyFreqReq* req, char** hdr_raw, uint32_t* len_hdr) {
  // Places null-terminated content of HTTP header into hdr_raw, perhaps
  // changing where it points to (realloc), without the trailing whitespace.
  // Returns the length of the header (negative for error) and modifies len_hdr
  // to communicate total size of the buffer.
  // NOTE: strongly assumes that we've just submitted a request and are free to
  //       read from the socket
  char connection_active = 1;     // Tells us when to bail out
  int sz = 0;                     // Amount downloaded
  int ret = 0;                    // Return value of ssl_read()
  char* hdr = *hdr_raw;
  char* p = hdr;                  // Points inside of hdr
  do {
    switch(ret=mbedtls_ssl_read(&req->ssl, hdr + sz, 1)) {
      case 1:
        break;
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // If we're here, we didn't read anything from the socket, so retry
        continue;
      case 0:
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        // These two cases are errors, since we haven't finished the header yet!
      default:  // negative -- error!
        return -2;
    }

    // We're done processing the mbedtls_ssl() return code, which means we had
    // a positive value (bytes read).  Reposition offsets and resize buffers.
    // NOTE: technically we gain extra padding with each iteration, since len
    //       accounted for a final null byte; this is ignored for clarity
    sz += ret;
    if(sz > *len_hdr - 5) {
      *len_hdr = expand(hdr_raw, *len_hdr);
      p = (p - hdr) + *hdr_raw;                // reposition
      hdr = *hdr_raw;
    }

    // Try to detect the end of the header.  If so, we're done!
    // hdr resizing logic ensures this won't overflow, and spec ensures only
    // TEXT (ASCII > 31) occurs in HTTP header, so we won't have '\0'
    while(p[3]) {
      if('\r' == p[0] && p[0] == p[2] &&
         '\n' == p[1] && p[1] == p[3]) {
        connection_active = 0;
        break;
      }
      p++;
    }
  } while(connection_active);

  return sz;
}

long BodyRip(EtsyFreqReq* req, char** bod_raw, uint32_t* len_bod, int len) {
  int sz = 0, ret = 0;
  char* bod = *bod_raw;

  // Make sure bod can serve as a sufficiently large buffer
  while(len > *len_bod) {
    *len_bod = expand(bod_raw, *len_bod);
    if(!*bod_raw) ;  // this is an error, but we don't handle it here
    bod = *bod_raw;
  }

  // Pull data from HTTPS into buf
  sz = 0;  // sz now tracks total downloaded into buf
  while(sz<len) {
    switch(ret=mbedtls_ssl_read(&req->ssl, bod + sz, len - sz)) {
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // If we're here, we didn't read anything from the socket, so retry
        continue;
      case 0:
        break;
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        return -4;
      default:
        if(0>ret) return -4;  // error
        sz += ret;
        continue;
    }

  }
  return sz;
}

long ChunkRip(EtsyFreqReq* req, char** buf_raw, uint32_t* len_buf) {
  int sz = 0, len_chunk = 0, ret = 0;
  char* buf = *buf_raw;
  memset(buf, 0, *len_buf);

  // Get the chunk metadata
  // Exit condition examples:
  // 123\r\n     // We are at top of chunk
  // \r\n123\r\n // We are at bottom of depleted chunk
  while(sz<3 || '\r' != buf[sz-2] || '\n' != buf[sz-1]) {
    switch(ret=mbedtls_ssl_read(&req->ssl, buf + sz, 1)) {
      case 1:
        sz += ret;
        if(sz>*len_buf){
          printf("WHOA!\n");
          printf("sz: %d, ret: %d, buf: %d\n", sz, ret, *len_buf);
          printf("%s\n", buf);
          fflush(stdout);
          exit(-1);
        }
        break;
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // If we're here, we didn't read anything from the socket, so retry
        continue;
      case 0:
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      default:
        // Shouldn't happen while processing chunk metadata!
        return -3;
    }
  }

  // Pull chunk into buf
  len_chunk = strtol(buf, NULL, 16);
  sz = 0;
  if(0 == len_chunk) return 0; // Communicates that we're done

  // Make sure buf can serve as a sufficiently large buffer for chunk
  while(len_chunk > *len_buf) {
    *len_buf = expand(buf_raw, *len_buf);
    if(!*buf_raw) ;  // this is an error, but we don't handle it here
    buf = *buf_raw;
  }

  // Pull data from HTTPS into buf
  sz = 0;  // sz now tracks total downloaded into buf
  while(sz<len_chunk) {
    switch(ret=mbedtls_ssl_read(&req->ssl, buf + sz, len_chunk - sz)) {
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // If we're here, we didn't read anything from the socket, so retry
        continue;
      case 0:
        break;
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        return -4;
      default:
        if(0>ret) return -4;  // error
        sz += ret;
        continue;
    }

  }
  return len_chunk;
}

long BodyRipChunked(EtsyFreqReq* req, char** bod_raw, uint32_t* len_bod) {
  // Since we pulled the header off the buffer on a byte-by-byte basis, the
  // underlying mbedssl connection starts with the top of the chunk header.  Now
  // we grab data byte-by-byte until we have the chunk header, then grab the
  // chunk and repeat.  Ideally, we'd stream the frequency analysis here, but I
  // don't want to write the state machine to keep track of all the different
  // processing-splitting issues, so I keep expanding a buffer until the whole
  // body of the current page fits there.
  char* buf = calloc(1,BUF_LEN);         // temp buffer
  uint32_t len_buf = BUF_LEN-1;          // keep track of buf len
  char* bod = *bod_raw;                  // clarifying placeholder
  long ret = 0, len = 0;                 // return and total length of body
  uint32_t pos_bod = 0;
  while(0<(ret=ChunkRip(req, &buf, &len_buf))) {
    len += ret;
    while(len > *len_bod - pos_bod) {
      *len_bod = expand(bod_raw, *len_bod);
      if(!*bod_raw) ;  // this is an error, but we don't handle it here
      bod = *bod_raw;
    }
    memcpy(bod + pos_bod, buf, ret);  // slot buf into body
    pos_bod += ret;
  }
  free(buf);

  // Check that we didn't hit any errors in ChunkRip
  return (0==ret) ? len : ret;
}

int EtsyFreqReqProcess(EtsyFreqReq* req) {
  // Send the request
  EtsyFreqReqSend(req);

  // Take the header off the request
  int rc = 0;
  char* hdr = calloc(1,BUF_LEN);  // header retrieval buffer
  char* bod = calloc(1,BUF_LEN);  // body   retrieval buffer
  uint32_t len_bod = BUF_LEN-1;   // keep track of body buffer length
  uint32_t len_hdr = BUF_LEN-1;
  HeaderRip(req, &hdr, &len_hdr);
  rc = HeaderGetEncoding(hdr);    // chunked or not?
  free(hdr);                      // not actually used!

  if(-1 == rc)
    BodyRipChunked(req, &bod, &len_bod);
  else
    BodyRip(req, &bod, &len_bod, rc);

  // `bod` contains the full text of the current page.  We run it through the
  // processor logic, which is split into a few passes.
  //  1. Detect the text and description sections, passing the text down to the
  //     next section
  //  2. Replace whitespace with ' '--including escaped sequences, XML/HTML
  //     character references, one-character words,
  //  3. Tokenize by space, taking non-null results into the trie
  char* p = bod;   // temp pointer
  int desc = 0;    // number of descriptions (unused)
  int words = 0;   // number of words
  while(p=JSONTextGet(p)) {                    // get next valid entry
    JSONTextClean(p);                          // convert non-words to spaces
    words+=JSONTextToHistogram(p, &req->hist); // tokenize + count words
    p += strlen(p)+1;                          // make sure we advance
    desc++;                                    // count how many descriptions
  }
  free(bod);
  return words;
}


/*---------------------------------------------------------------------------*\
|                                  Entrypoint                                 |
\*---------------------------------------------------------------------------*/
char* Stores[] = {
  "VintageRevivalFinds",
  "woodlandart53",
  "lukparts",
  "EmeraldGames",
  "NoTurnsCollectables",
  "NeedfulThingsByAnn",
  "StupidGeeks",
  "VintageBookworms",
  "customKraze",
  "OnlyTrueBlue"};

int main(int argc, char** argv) {
  // Check input
  if(argc<2) {
    printf("Please provide an API key.\n");
    return -1;
  }
  // Initialize mbedtls
  LibInit();

  for(int i=0; i<10; i++) {
    // Initialize the EtsyFreqReq object.
    EtsyFreqReq req = {0};
    req.store = Stores[i];
    req.key   = argv[1];
    req.limit = 500;
    EZTrieInit(&req.hist, 5);

    // Send the request, enumerating the result.  We set the connection to
    // be closed on the server side, so we reconnect every time.  This is because
    // I didn't want to figure out how to detect closure from mbedtls.
    int rc = 1;
    int words = 0;
    EtsyFreqReqInit(&req, SERVER_NAME, SERVER_PORT);  // connect
    while(0<rc) {
      rc=EtsyFreqReqProcess(&req);                    // send+process
      words += rc;                                    // running total of words
      req.offset++;                                   // advance
    }

    // Print out top words
    printf("Printing top words for %s (%d words observed)\n", Stores[i], words);
    for(int j=0; j<req.hist.sz_winners; j++) {
      char* word = NodeToWord(req.hist.winners[j]);
      uint64_t wcount = req.hist.winners[j]->count;
      double   freq   = ((double)wcount)/((double)words);
      printf("%25s: %10ld   %10f%%\n", word, wcount, 100*freq);
      free(word);
    }
    EtsyFreqReqFree(&req);
  }

  return 0;
}
