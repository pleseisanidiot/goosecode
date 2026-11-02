/* C shim for goosecode: HTTP (libcurl), OAuth loopback listener, SHA-256,
   subprocesses. Included after Goose's generated type declarations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <sys/wait.h>

static char *gc_dup(sl_u8 s) {
    char *p = (char *)malloc((size_t)s.len + 1);
    if (s.len) memcpy(p, s.data, (size_t)s.len);
    p[s.len] = 0;
    return p;
}

static size_t gc_write_cb(char *ptr, size_t sz, size_t n, void *ud) {
    gs_bld_append(*(gs_rref *)ud, ptr, sz * n);
    return sz * n;
}

/* POST `body` (content type `ctype`) to `url`; optional bearer token.
   Appends the response body to `out`; returns the HTTP status, 0 on a
   transport failure (then `out` gets curl's message). */
static int32_t gc_http_post(sl_u8 url, sl_u8 bearer, sl_u8 ctype, sl_u8 body, gs_rref out) {
    CURL *c = curl_easy_init();
    if (!c) return 0;
    char *u = gc_dup(url), *b = gc_dup(bearer), *ct = gc_dup(ctype), *d = gc_dup(body);
    struct curl_slist *h = NULL;
    char buf[8192];
    snprintf(buf, sizeof buf, "Content-Type: %s", ct);
    h = curl_slist_append(h, buf);
    if (bearer.len) { snprintf(buf, sizeof buf, "Authorization: Bearer %s", b); h = curl_slist_append(h, buf); }
    h = curl_slist_append(h, "HTTP-Referer: https://github.com/goosecode");
    h = curl_slist_append(h, "X-Title: goosecode");
    char err[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(c, CURLOPT_URL, u);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, d);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body.len);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, gc_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *)&out);
    curl_easy_setopt(c, CURLOPT_ERRORBUFFER, err);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 600L);
    CURLcode rc = curl_easy_perform(c);
    long status = 0;
    if (rc == CURLE_OK) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    else gs_bld_append(out, err[0] ? err : curl_easy_strerror(rc), strlen(err[0] ? err : curl_easy_strerror(rc)));
    curl_slist_free_all(h); curl_easy_cleanup(c);
    free(u); free(b); free(ct); free(d);
    return (int32_t)status;
}

static void gc_b64url(const unsigned char *in, size_t n, gs_rref out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char tmp[4];
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        tmp[0] = T[v >> 18 & 63]; tmp[1] = T[v >> 12 & 63]; tmp[2] = T[v >> 6 & 63]; tmp[3] = T[v & 63];
        size_t k = i + 2 < n ? 4 : (i + 1 < n ? 3 : 2);
        gs_bld_append(out, tmp, k);
    }
}

/* Appends base64url(SHA-256(s)), unpadded: the PKCE S256 challenge. */
static void gc_sha256_b64url(sl_u8 s, gs_rref out) {
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(s.data, (size_t)s.len, d);
    gc_b64url(d, sizeof d, out);
}

/* Appends base64url of n random bytes. */
static void gc_random_b64url(int64_t n, gs_rref out) {
    unsigned char b[256];
    if (n > 256) n = 256;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(b, 1, (size_t)n, f) != (size_t)n) { if (f) fclose(f); exit(1); }
    fclose(f);
    gc_b64url(b, (size_t)n, out);
}

/* Listens on 127.0.0.1:port for the OAuth redirect, appends the `code`
   query parameter, answers the browser. False on any failure. */
static uint8_t gc_oauth_wait(int32_t port, gs_rref out) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 4) < 0) { close(s); return 0; }
    uint8_t ok = 0;
    for (int tries = 0; tries < 20 && !ok; tries++) {
        int c = accept(s, NULL, NULL);
        if (c < 0) break;
        char req[8192]; ssize_t n = read(c, req, sizeof req - 1);
        if (n < 0) n = 0;
        req[n] = 0;
        char *p = strstr(req, "code=");
        const char *msg;
        if (p) {
            p += 5;
            size_t k = strcspn(p, "& \r\n");
            gs_bld_append(out, p, k);
            ok = 1;
            msg = "<html><body style='font-family:sans-serif'><h2>goosecode: logged in.</h2>You can close this tab.</body></html>";
        } else msg = "<html><body>waiting for OAuth code...</body></html>";
        char resp[1024];
        int m = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(msg), msg);
        if (write(c, resp, (size_t)m) < 0) {}
        close(c);
    }
    close(s);
    return ok;
}

static void gc_open_url(sl_u8 url) {
    char *u = gc_dup(url);
    char cmd[8192];
    snprintf(cmd, sizeof cmd, "xdg-open '%s' >/dev/null 2>&1 &", u);
    if (system(cmd)) {}
    free(u);
}

/* Runs a shell command, appends combined stdout+stderr (at most 60000
   bytes kept), returns the exit status. */
static int32_t gc_run(sl_u8 cmd, gs_rref out) {
    char *c0 = gc_dup(cmd);
    size_t cl = strlen(c0) + 32;
    char *c = (char *)malloc(cl);
    snprintf(c, cl, "( %s ) 2>&1 </dev/null", c0);
    FILE *f = popen(c, "r");
    free(c0); free(c);
    if (!f) return -1;
    char buf[4096]; size_t n, kept = 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (kept < 60000) { size_t k = n; if (kept + k > 60000) k = 60000 - kept; gs_bld_append(out, buf, k); kept += k; }
    }
    int st = pclose(f);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

#include <readline/readline.h>
#include <readline/history.h>

/* ---- Ctrl-C, spinner ---------------------------------------------------- */
#include <signal.h>
#include <pthread.h>
#include <time.h>

static volatile sig_atomic_t gc_cancel = 0;
static volatile sig_atomic_t gc_at_prompt = 0;

static void gc_sigint(int sig) {
    (void)sig;
    if (gc_at_prompt) {
        if (write(1, "^C\n", 3)) {}
        rl_replace_line("", 0); rl_on_new_line(); rl_redisplay();
    } else gc_cancel = 1;
}
static void gc_init_signals(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = gc_sigint; sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    rl_catch_signals = 0;
}
static uint8_t gc_cancelled(void) { return gc_cancel ? 1 : 0; }
static void gc_clear_cancel(void) { gc_cancel = 0; }

static pthread_t gc_spin_th; static volatile int gc_spin_on = 0; static char gc_spin_label[128];
static void *gc_spin_run(void *arg) {
    (void)arg;
    static const char *F[] = {"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"};
    struct timespec ts = {0, 80000000};
    for (int i = 0; gc_spin_on; i++) {
        printf("\r\x1b[36m%s\x1b[0m \x1b[2m%s (Ctrl-C to cancel)\x1b[0m\x1b[K", F[i % 10], gc_spin_label);
        fflush(stdout);
        nanosleep(&ts, NULL);
    }
    return NULL;
}
static void gc_spinner_start_c(const char *label) {
    if (gc_spin_on || !isatty(1)) return;
    snprintf(gc_spin_label, sizeof gc_spin_label, "%s", label);
    gc_spin_on = 1;
    pthread_create(&gc_spin_th, NULL, gc_spin_run, NULL);
}
static void gc_spinner_stop(void) {
    if (!gc_spin_on) return;
    gc_spin_on = 0;
    pthread_join(gc_spin_th, NULL);
    fputs("\r\x1b[K", stdout); fflush(stdout);
}
static void gc_spinner_start(sl_u8 label) { char *l = gc_dup(label); gc_spinner_start_c(l); free(l); }

static int gc_xfer_cb(void *p, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    (void)p; (void)a; (void)b; (void)c; (void)d;
    return gc_cancel ? 1 : 0;
}

/* GET (no auth); appends the body; returns the HTTP status. */
static int32_t gc_http_get(sl_u8 url, gs_rref out) {
    CURL *c = curl_easy_init();
    if (!c) return 0;
    char *u = gc_dup(url);
    curl_easy_setopt(c, CURLOPT_URL, u);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, gc_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *)&out);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    CURLcode rc = curl_easy_perform(c);
    long status = 0;
    if (rc == CURLE_OK) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(c); free(u);
    return (int32_t)status;
}

/* ---- streaming ---------------------------------------------------------- */

static char *gc_sbuf = NULL; static size_t gc_slen = 0, gc_scap = 0;
static int gc_first_tok = 1;

static void gc_emit_content(const char *line) {
    const char *d = strstr(line, "\"delta\"");
    if (!d) return;
    const char *p = strstr(d, "\"content\"");
    if (!p) return;
    p += 9;
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return;
    p++;
    if (gc_first_tok) { gc_spinner_stop(); gc_first_tok = 0; }
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': putchar('\n'); break;
            case 't': putchar('\t'); break;
            case 'r': break;
            case 'u': {
                unsigned cp = 0; sscanf(p + 1, "%4x", &cp); p += 4;
                if (cp >= 0xD800 && cp < 0xDC00 && p[1] == '\\' && p[2] == 'u') {
                    unsigned lo = 0; sscanf(p + 3, "%4x", &lo); p += 6;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                if (cp < 0x80) putchar((int)cp);
                else if (cp < 0x800) { putchar(0xC0 | cp >> 6); putchar(0x80 | (cp & 63)); }
                else if (cp < 0x10000) { putchar(0xE0 | cp >> 12); putchar(0x80 | (cp >> 6 & 63)); putchar(0x80 | (cp & 63)); }
                else { putchar(0xF0 | cp >> 18); putchar(0x80 | (cp >> 12 & 63)); putchar(0x80 | (cp >> 6 & 63)); putchar(0x80 | (cp & 63)); }
                break; }
            default: putchar(*p);
            }
            p++;
        } else putchar(*p++);
    }
    fflush(stdout);
}

typedef struct { gs_rref out; } gc_sctx;
static size_t gc_stream_cb(char *ptr, size_t sz, size_t n, void *ud) {
    size_t total = sz * n;
    gs_bld_append(((gc_sctx *)ud)->out, ptr, total);
    if (gc_slen + total + 1 > gc_scap) { gc_scap = (gc_slen + total + 1) * 2; gc_sbuf = (char *)realloc(gc_sbuf, gc_scap); }
    memcpy(gc_sbuf + gc_slen, ptr, total); gc_slen += total; gc_sbuf[gc_slen] = 0;
    char *start = gc_sbuf, *nl;
    while ((nl = memchr(start, '\n', gc_slen - (size_t)(start - gc_sbuf)))) {
        *nl = 0;
        if (!strncmp(start, "data: {", 7)) gc_emit_content(start);
        start = nl + 1;
    }
    gc_slen -= (size_t)(start - gc_sbuf);
    memmove(gc_sbuf, start, gc_slen); gc_sbuf[gc_slen] = 0;
    return total;
}

/* Like gc_http_post but the body is an SSE stream: content deltas are
   printed live; the raw stream is appended to `out`. */
static int32_t gc_http_stream(sl_u8 url, sl_u8 bearer, sl_u8 body, gs_rref out) {
    CURL *c = curl_easy_init();
    if (!c) return 0;
    char *u = gc_dup(url), *b = gc_dup(bearer), *d = gc_dup(body);
    struct curl_slist *h = NULL;
    char buf[8192];
    h = curl_slist_append(h, "Content-Type: application/json");
    snprintf(buf, sizeof buf, "Authorization: Bearer %s", b); h = curl_slist_append(h, buf);
    h = curl_slist_append(h, "HTTP-Referer: https://github.com/goosecode");
    h = curl_slist_append(h, "X-Title: goosecode");
    gc_sctx ctx = { out }; gc_slen = 0; gc_first_tok = 1; gc_cancel = 0;
    gc_spinner_start_c("thinking");
    char err[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(c, CURLOPT_URL, u);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, d);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body.len);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, gc_stream_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, gc_xfer_cb);
    curl_easy_setopt(c, CURLOPT_ERRORBUFFER, err);
    CURLcode rc = curl_easy_perform(c);
    long status = 0;
    if (rc == CURLE_OK) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    else if (rc == CURLE_ABORTED_BY_CALLBACK) status = 499;
    else gs_bld_append(out, err, strlen(err));
    gc_spinner_stop();
    if (!gc_first_tok) putchar('\n');
    fflush(stdout);
    curl_slist_free_all(h); curl_easy_cleanup(c);
    free(u); free(b); free(d);
    return (int32_t)status;
}

static char *gc_hist_path = NULL;

/* Loads the history file (creating it) and remembers it for later appends. */
static void gc_history_init(sl_u8 path) {
    gc_hist_path = gc_dup(path);
    stifle_history(1000);
    if (read_history(gc_hist_path)) write_history(gc_hist_path);
}

static uint8_t gc_prompt(sl_u8 prompt, gs_rref out, int remember) {
    char *p = gc_dup(prompt);
    gc_at_prompt = 1;
    char *l = readline(p);
    gc_at_prompt = 0;
    free(p);
    if (!l) return 0;
    if (remember && *l) {
        add_history(l);
        if (gc_hist_path) append_history(1, gc_hist_path);
    }
    gs_bld_append(out, l, strlen(l));
    free(l);
    return 1;
}

/* Line editing; the line goes into the persistent history. False at EOF. */
static uint8_t gc_readline(sl_u8 prompt, gs_rref out) { return gc_prompt(prompt, out, 1); }
/* The same without recording the answer (confirmations, pickers). */
static uint8_t gc_ask(sl_u8 prompt, gs_rref out) { return gc_prompt(prompt, out, 0); }
