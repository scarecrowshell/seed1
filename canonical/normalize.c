// canonical/normalize.c
#define _GNU_SOURCE
#include "normalize.h"
#include "mod.h"        // provides CANONICAL_OK and CANONICAL_ERR_* macros
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <math.h>       // floor()

/* -------------------------
   Tiny JSON parser (supports what we need)
   ------------------------- */

typedef enum { JNULL, JBOOL, JNUMBER, JSTRING, JARRAY, JOBJECT } jtype_t;

typedef struct jval jval;
typedef struct kv { char *k; jval *v; } kv;

struct jval {
    jtype_t t;
    union {
        int b;
        double n;
        char *s;
        struct { jval **items; size_t count; } arr;
        struct { kv *items; size_t count; } obj;
    } u;
};

static void jval_free(jval *v);

/* parser state */
typedef struct {
    const char *p;
    const char *end;
    size_t pos;
} jctx;

static void skip_ws(jctx *c) {
    while (c->p < c->end && (*c->p==' '||*c->p=='\n'||*c->p=='\r'||*c->p=='\t')) { c->p++; c->pos++; }
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* append UTF-8 encoding of codepoint to buffer (dynamic) */
static int append_utf8(char **buf, size_t *len, size_t *cap, uint32_t cp) {
    unsigned char tmp[4];
    int n = 0;
    if (cp <= 0x7F) { tmp[n++]=(char)cp; }
    else if (cp <= 0x7FF) { tmp[n++]=0xC0 | (cp>>6); tmp[n++]=0x80 | (cp & 0x3F); }
    else if (cp <= 0xFFFF) { tmp[n++]=0xE0 | (cp>>12); tmp[n++]=0x80 | ((cp>>6)&0x3F); tmp[n++]=0x80 | (cp & 0x3F); }
    else { tmp[n++]=0xF0 | (cp>>18); tmp[n++]=0x80 | ((cp>>12)&0x3F); tmp[n++]=0x80 | ((cp>>6)&0x3F); tmp[n++]=0x80 | (cp & 0x3F); }
    if (*len + n >= *cap) {
        size_t newcap = (*cap==0) ? 256 : (*cap * 2);
        while (*len + n >= newcap) newcap *= 2;
        char *nb = realloc(*buf, newcap);
        if (!nb) return -1;
        *buf = nb; *cap = newcap;
    }
    memcpy(*buf + *len, tmp, n);
    *len += n;
    return 0;
}

static char *parse_json_string(jctx *c) {
    if (c->p >= c->end || *c->p != '"') return NULL;
    c->p++; c->pos++;
    char *buf = NULL; size_t len = 0, cap = 0;
    while (c->p < c->end) {
        char ch = *c->p++;
        c->pos++;
        if (ch == '"') {
            if (buf == NULL) { buf = malloc(1); if (!buf) return NULL; buf[0]=0; }
            else {
                if (len + 1 >= cap) { char *nb = realloc(buf, len+1); if (!nb) { free(buf); return NULL; } buf = nb; cap = len+1; }
                buf[len] = '\0';
            }
            return buf;
        } else if (ch == '\\') {
            if (c->p >= c->end) { free(buf); return NULL; }
            char esc = *c->p++; c->pos++;
            if (esc == '"' || esc == '\\' || esc == '/' ) {
                if (len + 1 >= cap) { size_t nc = (cap==0)?256:cap*2; char *nb = realloc(buf, nc); if (!nb) { free(buf); return NULL; } buf = nb; cap = nc; }
                buf[len++] = esc;
            } else if (esc == 'b') {
                if (len + 1 >= cap) { size_t nc=(cap==0)?256:cap*2; char *nb=realloc(buf,nc); if(!nb){free(buf);return NULL;} buf=nb; cap=nc; }
                buf[len++] = '\b';
            } else if (esc == 'f') {
                if (len + 1 >= cap) { size_t nc=(cap==0)?256:cap*2; char *nb=realloc(buf,nc); if(!nb){free(buf);return NULL;} buf=nb; cap=nc; }
                buf[len++] = '\f';
            } else if (esc == 'n') {
                if (len + 1 >= cap) { size_t nc=(cap==0)?256:cap*2; char *nb=realloc(buf,nc); if(!nb){free(buf);return NULL;} buf=nb; cap=nc; }
                buf[len++] = '\n';
            } else if (esc == 'r') {
                if (len + 1 >= cap) { size_t nc=(cap==0)?256:cap*2; char *nb=realloc(buf,nc); if(!nb){free(buf);return NULL;} buf=nb; cap=nc; }
                buf[len++] = '\r';
            } else if (esc == 't') {
                if (len + 1 >= cap) { size_t nc=(cap==0)?256:cap*2; char *nb=realloc(buf,nc); if(!nb){free(buf);return NULL;} buf=nb; cap=nc; }
                buf[len++] = '\t';
            } else if (esc == 'u') {
                if (c->p + 4 > c->end) { free(buf); return NULL; }
                int h1 = hexval(c->p[0]); int h2 = hexval(c->p[1]); int h3 = hexval(c->p[2]); int h4 = hexval(c->p[3]);
                if (h1<0 || h2<0 || h3<0 || h4<0) { free(buf); return NULL; }
                uint32_t cp = (h1<<12)|(h2<<8)|(h3<<4)|h4;
                c->p += 4; c->pos += 4;
                if (append_utf8(&buf, &len, &cap, cp) != 0) { free(buf); return NULL; }
            } else {
                free(buf); return NULL;
            }
        } else {
            if (len + 1 >= cap) { size_t nc = (cap==0)?256:cap*2; char *nb = realloc(buf, nc); if (!nb) { free(buf); return NULL; } buf = nb; cap = nc; }
            buf[len++] = ch;
        }
    }
    free(buf);
    return NULL;
}

static jval *parse_value(jctx *c);

static jval *parse_array(jctx *c) {
    // expects '[' on entry
    if (c->p >= c->end || *c->p != '[') return NULL;
    c->p++; c->pos++;
    skip_ws(c);
    jval **items = NULL; size_t cnt = 0, cap = 0;
    if (c->p < c->end && *c->p == ']') { c->p++; c->pos++; jval *v = malloc(sizeof(jval)); if(!v) return NULL; v->t = JARRAY; v->u.arr.items = NULL; v->u.arr.count = 0; return v; }
    while (c->p < c->end) {
        skip_ws(c);
        jval *elem = parse_value(c);
        if (!elem) {
            if (items) {
                for (size_t i=0;i<cnt;i++) { jval_free(items[i]); }
                free(items);
            }
            return NULL;
        }
        if (cnt + 1 > cap) {
            size_t nc = (cap==0)?8:cap*2;
            jval **nb = realloc(items, nc * sizeof(jval*));
            if (!nb) { jval_free(elem); if (items) { for (size_t i=0;i<cnt;i++) { jval_free(items[i]); } free(items);} return NULL; }
            items = nb; cap = nc;
        }
        items[cnt++] = elem;
        skip_ws(c);
        if (c->p < c->end && *c->p == ',') { c->p++; c->pos++; continue; }
        if (c->p < c->end && *c->p == ']') { c->p++; c->pos++; break; }
        // unexpected
        for (size_t i=0;i<cnt;i++) { jval_free(items[i]); }
        free(items);
        return NULL;
    }
    jval *v = malloc(sizeof(jval)); if (!v) { for (size_t i=0;i<cnt;i++) jval_free(items[i]); free(items); return NULL; }
    v->t = JARRAY; v->u.arr.items = items; v->u.arr.count = cnt; return v;
}

static jval *parse_object(jctx *c) {
    if (c->p >= c->end || *c->p != '{') return NULL;
    c->p++; c->pos++;
    skip_ws(c);
    kv *items = NULL; size_t cnt=0, cap=0;
    if (c->p < c->end && *c->p == '}') { c->p++; c->pos++; jval *v=malloc(sizeof(jval)); if(!v) return NULL; v->t=JOBJECT; v->u.obj.items=NULL; v->u.obj.count=0; return v; }
    while (c->p < c->end) {
        skip_ws(c);
        char *key = parse_json_string(c);
        if (!key) {
            if (items) {
                for (size_t i=0;i<cnt;i++){ free(items[i].k); jval_free(items[i].v); }
                free(items);
            }
            return NULL;
        }
        skip_ws(c);
        if (c->p >= c->end || *c->p != ':') { free(key); if (items) { for (size_t i=0;i<cnt;i++){ free(items[i].k); jval_free(items[i].v);} free(items); } return NULL; }
        c->p++; c->pos++;
        skip_ws(c);
        jval *val = parse_value(c);
        if (!val) { free(key); if (items) { for (size_t i=0;i<cnt;i++){ free(items[i].k); jval_free(items[i].v);} free(items); } return NULL; }
        if (cnt + 1 > cap) {
            size_t nc = (cap==0)?8:cap*2;
            kv *nb = realloc(items, nc * sizeof(kv));
            if (!nb) { free(key); jval_free(val); if (items) { for (size_t i=0;i<cnt;i++){ free(items[i].k); jval_free(items[i].v);} free(items); } return NULL; }
            items = nb; cap = nc;
        }
        items[cnt].k = key;
        items[cnt].v = val;
        cnt++;
        skip_ws(c);
        if (c->p < c->end && *c->p == ',') { c->p++; c->pos++; continue; }
        if (c->p < c->end && *c->p == '}') { c->p++; c->pos++; break; }
        // unexpected
        for (size_t i=0;i<cnt;i++){ free(items[i].k); jval_free(items[i].v); }
        free(items);
        return NULL;
    }
    jval *v = malloc(sizeof(jval)); if (!v) { for (size_t i=0;i<cnt;i++){ free(items[i].k); jval_free(items[i].v);} free(items); return NULL; }
    v->t = JOBJECT; v->u.obj.items = items; v->u.obj.count = cnt; return v;
}

static jval *parse_number(jctx *c) {
    const char *start = c->p;
    int seen_dot = 0, seen_exp = 0;
    if (c->p < c->end && (*c->p=='-'||*c->p=='+')) { c->p++; c->pos++; }
    while (c->p < c->end) {
        char ch = *c->p;
        if (ch >= '0' && ch <= '9') { c->p++; c->pos++; continue; }
        if (ch == '.' && !seen_dot) { seen_dot = 1; c->p++; c->pos++; continue; }
        if ((ch == 'e' || ch=='E') && !seen_exp) { seen_exp = 1; c->p++; c->pos++; if (c->p < c->end && (*c->p=='+'||*c->p=='-')) { c->p++; c->pos++; } continue; }
        break;
    }
    size_t len = c->p - start;
    char *numbuf = malloc(len+1);
    if (!numbuf) return NULL;
    memcpy(numbuf, start, len); numbuf[len]=0;
    char *endptr;
    double dv = strtod(numbuf, &endptr);
    free(numbuf);
    jval *v = malloc(sizeof(jval));
    if (!v) return NULL;
    v->t = JNUMBER; v->u.n = dv; return v;
}

static jval *parse_value(jctx *c) {
    skip_ws(c);
    if (c->p >= c->end) return NULL;
    char ch = *c->p;
    if (ch == '{') return parse_object(c);
    if (ch == '[') return parse_array(c);
    if (ch == '"') {
        char *s = parse_json_string(c);
        if (!s) return NULL;
        jval *v = malloc(sizeof(jval));
        if (!v) { free(s); return NULL; }
        v->t = JSTRING; v->u.s = s; return v;
    }
    if (ch == 't' && c->p+4 <= c->end && strncmp(c->p, "true", 4)==0) { c->p+=4; c->pos+=4; jval *v=malloc(sizeof(jval)); if(!v) return NULL; v->t=JBOOL; v->u.b=1; return v; }
    if (ch == 'f' && c->p+5 <= c->end && strncmp(c->p, "false", 5)==0) { c->p+=5; c->pos+=5; jval *v=malloc(sizeof(jval)); if(!v) return NULL; v->t=JBOOL; v->u.b=0; return v; }
    if (ch == 'n' && c->p+4 <= c->end && strncmp(c->p, "null", 4)==0) { c->p+=4; c->pos+=4; jval *v=malloc(sizeof(jval)); if(!v) return NULL; v->t=JNULL; return v; }
    if ( (ch=='-') || (ch>='0' && ch<='9') ) return parse_number(c);
    return NULL;
}

static void jval_free(jval *v) {
    if (!v) return;
    switch (v->t) {
        case JSTRING: free(v->u.s); break;
        case JARRAY:
            for (size_t i=0;i<v->u.arr.count;i++) jval_free(v->u.arr.items[i]);
            free(v->u.arr.items);
            break;
        case JOBJECT:
            for (size_t i=0;i<v->u.obj.count;i++) { free(v->u.obj.items[i].k); jval_free(v->u.obj.items[i].v); }
            free(v->u.obj.items);
            break;
        default: break;
    }
    free(v);
}

/* -------------------------
   Simple string normalization:
   - Trim leading/trailing ASCII whitespace
   - Collapse runs of ASCII whitespace (space, tab, newline) into single space
   Note: does NOT perform Unicode NFC (left as TODO)
   ------------------------- */

static char *normalize_string_canonical(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *tmp = malloc(n+1);
    if (!tmp) return NULL;
    size_t wi = 0;
    int in_ws = 0;
    for (size_t i=0;i<n;i++) {
        unsigned char c = s[i];
        int is_ws = (c==' '||c=='\t'||c=='\n'||c=='\r');
        if (is_ws) {
            if (!in_ws) { tmp[wi++] = ' '; in_ws = 1; }
        } else {
            tmp[wi++] = c; in_ws = 0;
        }
    }
    // trim leading/trailing space
    size_t start = 0;
    while (start < wi && tmp[start] == ' ') start++;
    size_t end = wi;
    while (end > start && tmp[end-1] == ' ') end--;
    size_t outlen = (end > start) ? (end - start) : 0;
    char *out = malloc(outlen + 1);
    if (!out) { free(tmp); return NULL; }
    if (outlen > 0) memcpy(out, tmp + start, outlen);
    out[outlen] = '\0';
    free(tmp);
    return out;
}

/* -------------------------
   Deterministic serializer helpers (append to dynamic buffer)
   Field encoding approach (stable):
   - For each field (in schema order):
     - 2 bytes: field id (big-endian)
     - 1 byte: type tag (our can_type_t value)
     - for values:
        * STRING/BYTES: 4-byte length (BE) + raw bytes
        * U32: 4-byte unsigned BE
        * U64/I64: 8-byte BE (unsigned for U64, two's complement for I64)
        * BOOL: 1 byte 0/1
        * LIST: 4-byte count + each element encoded according to child schema (for entry list)
        * OBJECT: nested fields serialized according to child schema
   ------------------------- */

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} wbuf;

static int wbuf_init(wbuf *w) { w->buf = NULL; w->len = 0; w->cap = 0; return 0; }
static void wbuf_free(wbuf *w) { free(w->buf); w->buf = NULL; w->len = 0; w->cap = 0; }

static int wbuf_ensure(wbuf *w, size_t extra) {
    if (w->len + extra <= w->cap) return 0;
    size_t nc = (w->cap==0) ? 1024 : w->cap * 2;
    while (w->len + extra > nc) nc *= 2;
    uint8_t *nb = realloc(w->buf, nc);
    if (!nb) return -1;
    w->buf = nb; w->cap = nc; return 0;
}

static int wbuf_put(wbuf *w, const void *data, size_t n) {
    if (wbuf_ensure(w, n) != 0) return -1;
    memcpy(w->buf + w->len, data, n); w->len += n; return 0;
}
static int wbuf_put_u8(wbuf *w, uint8_t v) { return wbuf_put(w, &v, 1); }
static int wbuf_put_u32be(wbuf *w, uint32_t v) {
    uint8_t b[4]; b[0] = (v >> 24) & 0xFF; b[1] = (v >> 16) & 0xFF; b[2] = (v >> 8) & 0xFF; b[3] = v & 0xFF;
    return wbuf_put(w, b, 4);
}
static int wbuf_put_u64be(wbuf *w, uint64_t v) {
    uint8_t b[8];
    b[0] = (v >> 56) & 0xFF; b[1] = (v >> 48) & 0xFF; b[2] = (v >> 40) & 0xFF; b[3] = (v >> 32) & 0xFF;
    b[4] = (v >> 24) & 0xFF; b[5] = (v >> 16) & 0xFF; b[6] = (v >> 8) & 0xFF; b[7] = v & 0xFF;
    return wbuf_put(w, b, 8);
}
static int wbuf_put_i64be(wbuf *w, int64_t v) {
    return wbuf_put_u64be(w, (uint64_t)v);
}

/* -------------------------
   Lookup helpers on parsed object
   ------------------------- */

static jval *obj_lookup(jval *obj, const char *key) {
    if (!obj || obj->t != JOBJECT) return NULL;
    for (size_t i=0;i<obj->u.obj.count;i++) {
        if (strcmp(obj->u.obj.items[i].k, key) == 0) return obj->u.obj.items[i].v;
    }
    return NULL;
}

/* -------------------------
   Serialize according to schema (seed.manifest v1 & entry.v1)
   ------------------------- */

static int serialize_entry_v1(jval *val_obj, wbuf *out, canonical_result_t *res) {
    if (!val_obj || val_obj->t != JOBJECT) { res->code = CANONICAL_ERR_SERIALIZE; snprintf(res->message, sizeof(res->message),"entry not object"); return -1; }
    const can_schema_t *s = can_schema_lookup("entry", 1);
    if (!s) { res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message, sizeof(res->message),"entry schema missing"); return -1; }

    for (size_t i=0;i<s->field_count;i++) {
        const can_field_t *f = &s->fields[i];
        jval *v = obj_lookup(val_obj, f->name);
        // required check
        if (f->required && !v) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message, sizeof(res->message),"entry missing required '%s'", f->name); return -1; }
        // write field id (2 bytes) and type (1 byte)
        uint8_t fid[2] = { (uint8_t)((f->id>>8)&0xFF), (uint8_t)(f->id & 0xFF) };
        if (wbuf_put(out, fid, 2) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        if (wbuf_put_u8(out, (uint8_t)f->type) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }

        if (!v) {
            // absent optional field -> length 0 encoding (for strings/bytes) or zero for numbers/bools
            switch (f->type) {
                case CAN_TYPE_STRING: wbuf_put_u32be(out, 0); break;
                case CAN_TYPE_BYTES:  wbuf_put_u32be(out, 0); break;
                case CAN_TYPE_U32:    wbuf_put_u32be(out, 0); break;
                case CAN_TYPE_U64:    wbuf_put_u64be(out, 0); break;
                case CAN_TYPE_I64:    wbuf_put_i64be(out, 0); break;
                case CAN_TYPE_BOOL:   wbuf_put_u8(out, 0); break;
                default: break;
            }
            continue;
        }

        // encode based on type
        if (f->type == CAN_TYPE_STRING) {
            if (v->t != JSTRING) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected string", f->name); return -1; }
            char *norm = normalize_string_canonical(v->u.s);
            if (!norm) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
            uint32_t L = (uint32_t)strlen(norm);
            if (wbuf_put_u32be(out, L) != 0) { free(norm); res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
            if (L > 0) { if (wbuf_put(out, norm, L) != 0) { free(norm); res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; } }
            free(norm);
        } else if (f->type == CAN_TYPE_BOOL) {
            if (v->t != JBOOL) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected bool", f->name); return -1; }
            if (wbuf_put_u8(out, (uint8_t)(v->u.b?1:0)) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_U32) {
            if (v->t != JNUMBER) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected number", f->name); return -1; }
            double dv = v->u.n;
            if (dv < 0 || dv > 0xFFFFFFFF || dv != floor(dv)) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' not valid U32", f->name); return -1; }
            uint32_t val = (uint32_t)dv;
            if (wbuf_put_u32be(out, val) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_U64) {
            if (v->t != JNUMBER) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected number", f->name); return -1; }
            double dv = v->u.n;
            if (dv < 0 || dv > 18446744073709551615.0 || dv != floor(dv)) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' not valid U64", f->name); return -1; }
            uint64_t val = (uint64_t)dv;
            if (wbuf_put_u64be(out, val) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_I64) {
            if (v->t != JNUMBER) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected number", f->name); return -1; }
            double dv = v->u.n;
            if (dv < -9223372036854775807.0 - 1.0 || dv > 9223372036854775807.0 || dv != floor(dv)) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' not valid I64", f->name); return -1; }
            int64_t val = (int64_t)dv;
            if (wbuf_put_i64be(out, val) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_LIST) {
            if (!f->child_schema) { res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message,sizeof(res->message),"list missing child schema"); return -1; }
            if (v->t != JARRAY) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected array", f->name); return -1; }
            uint32_t count = (uint32_t)v->u.arr.count;
            if (wbuf_put_u32be(out, count) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
            for (size_t i=0;i<v->u.arr.count;i++) {
                jval *elem = v->u.arr.items[i];
                if (strcmp(f->child_schema, "entry.v1") == 0 || strcmp(f->child_schema, "entry") == 0) {
                    if (serialize_entry_v1(elem, out, res) != 0) return -1;
                } else {
                    res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message,sizeof(res->message),"unsupported child schema %s", f->child_schema); return -1;
                }
            }
        } else {
            res->code = CANONICAL_ERR_SCHEMA;
            snprintf(res->message, sizeof(res->message), "unsupported field type in entry for '%s'", f->name);
            return -1;
        }
    }
    return 0;
}

static int serialize_seed_manifest(jval *root_obj, wbuf *out, canonical_result_t *res) {
    if (!root_obj || root_obj->t != JOBJECT) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"root not object"); return -1; }
    const can_schema_t *s = can_schema_lookup("seed.manifest", 1);
    if (!s) { res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message,sizeof(res->message),"seed.manifest schema missing"); return -1; }

    for (size_t i=0;i<s->field_count;i++) {
        const can_field_t *f = &s->fields[i];
        jval *v = obj_lookup(root_obj, f->name);
        if (f->required && !v) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"missing required '%s'", f->name); return -1; }
        // write field id (2 bytes) and type (1 byte)
        uint8_t fid[2] = { (uint8_t)((f->id>>8)&0xFF), (uint8_t)(f->id & 0xFF) };
        if (wbuf_put(out, fid, 2) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        if (wbuf_put_u8(out, (uint8_t)f->type) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }

        if (!v) {
            // absent optional field
            switch (f->type) {
                case CAN_TYPE_STRING: wbuf_put_u32be(out, 0); break;
                case CAN_TYPE_LIST: wbuf_put_u32be(out, 0); break;
                case CAN_TYPE_U32: wbuf_put_u32be(out, 0); break;
                case CAN_TYPE_U64: wbuf_put_u64be(out, 0); break;
                case CAN_TYPE_I64: wbuf_put_i64be(out, 0); break;
                case CAN_TYPE_BOOL: wbuf_put_u8(out, 0); break;
                default: break;
            }
            continue;
        }

        if (f->type == CAN_TYPE_STRING) {
            if (v->t != JSTRING) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected string", f->name); return -1; }
            char *norm = normalize_string_canonical(v->u.s);
            if (!norm) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
            uint32_t L = (uint32_t)strlen(norm);
            if (wbuf_put_u32be(out, L) != 0) { free(norm); res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
            if (L>0) { if (wbuf_put(out, norm, L) != 0) { free(norm); res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; } }
            free(norm);
        } else if (f->type == CAN_TYPE_U32) {
            if (v->t != JNUMBER) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected number", f->name); return -1; }
            double dv = v->u.n;
            if (dv < 0 || dv > 0xFFFFFFFF || dv != floor(dv)) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' not valid U32", f->name); return -1; }
            uint32_t val = (uint32_t)dv;
            if (wbuf_put_u32be(out, val) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_I64) {
            if (v->t != JNUMBER) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected number", f->name); return -1; }
            double dv = v->u.n;
            if (dv != floor(dv) || dv < -9223372036854775807.0 - 1.0 || dv > 9223372036854775807.0) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' not valid I64", f->name); return -1; }
            int64_t val = (int64_t)dv;
            if (wbuf_put_i64be(out, val) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_LIST) {
            if (!f->child_schema) { res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message,sizeof(res->message),"list missing child schema"); return -1; }
            if (v->t != JARRAY) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected array", f->name); return -1; }
            uint32_t cnt = (uint32_t)v->u.arr.count;
            if (wbuf_put_u32be(out, cnt) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
            for (size_t i=0;i<v->u.arr.count;i++) {
                jval *elem = v->u.arr.items[i];
                if (strcmp(f->child_schema, "entry.v1") == 0 || strcmp(f->child_schema, "entry") == 0) {
                    if (serialize_entry_v1(elem, out, res) != 0) return -1;
                } else {
                    res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message,sizeof(res->message),"unsupported child schema %s", f->child_schema); return -1;
                }
            }
        } else if (f->type == CAN_TYPE_U64) {
            if (v->t != JNUMBER) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected number",f->name); return -1; }
            double dv = v->u.n;
            if (dv < 0 || dv > 18446744073709551615.0 || dv != floor(dv)) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' not valid U64", f->name); return -1; }
            uint64_t val = (uint64_t)dv;
            if (wbuf_put_u64be(out, val) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else if (f->type == CAN_TYPE_BOOL) {
            if (v->t != JBOOL) { res->code = CANONICAL_ERR_NORMALIZE; snprintf(res->message,sizeof(res->message),"field '%s' expected bool",f->name); return -1; }
            if (wbuf_put_u8(out, (uint8_t)(v->u.b?1:0)) != 0) { res->code = CANONICAL_ERR_INTERNAL; snprintf(res->message,sizeof(res->message),"oom"); return -1; }
        } else {
            res->code = CANONICAL_ERR_SCHEMA; snprintf(res->message,sizeof(res->message),"unsupported field type for '%s'", f->name); return -1;
        }
    }
    return 0;
}

/* -------------------------
   Top-level API
   ------------------------- */

int normalize_seed_manifest_and_serialize(const char *input,
                                          size_t input_len,
                                          uint8_t **out,
                                          size_t *outlen,
                                          canonical_result_t *result)
{
    if (!input || input_len == 0 || !out || !outlen || !result) return CANONICAL_ERR_INTERNAL;
    memset(result, 0, sizeof(*result));
    result->input_bytes = input_len;

    jctx ctx = { .p = input, .end = input + input_len, .pos = 0 };
    skip_ws(&ctx);
    jval *root = parse_value(&ctx);
    if (!root) {
        result->code = CANONICAL_ERR_NORMALIZE;
        snprintf(result->message, sizeof(result->message), "parse error");
        return result->code;
    }
    // ensure we consumed (or only trailing whitespace)
    skip_ws(&ctx);
    if (ctx.p != ctx.end) {
        jval_free(root);
        result->code = CANONICAL_ERR_NORMALIZE;
        snprintf(result->message, sizeof(result->message), "trailing data after JSON");
        return result->code;
    }

    // Must be object
    if (root->t != JOBJECT) {
        jval_free(root);
        result->code = CANONICAL_ERR_NORMALIZE;
        snprintf(result->message, sizeof(result->message), "root not object");
        return result->code;
    }

    // Serialize according to schema
    wbuf outw; if (wbuf_init(&outw)!=0) { jval_free(root); result->code = CANONICAL_ERR_INTERNAL; snprintf(result->message,sizeof(result->message),"oom"); return result->code; }
    int rc = serialize_seed_manifest(root, &outw, result);
    if (rc != 0) {
        wbuf_free(&outw);
        jval_free(root);
        return result->code ? result->code : CANONICAL_ERR_SERIALIZE;
    }

    *out = outw.buf;
    *outlen = outw.len;
    result->output_bytes = outw.len;
    result->schema_version = 1;
    result->code = CANONICAL_OK;
    snprintf(result->message, sizeof(result->message), "normalize+serialize OK");

    jval_free(root);
    return CANONICAL_OK;
}
