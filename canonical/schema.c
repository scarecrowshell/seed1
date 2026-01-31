// canonical/schema.c
// Static schema registry implementation for canonical types.
// - No dynamic allocation
// - Deterministic, frozen definitions suitable as the single source of truth
// - Includes a minimal seed.manifest.v1 and entry.v1 schema for inventory manifests

#include "schema.h"
#include <string.h>

/* -------------------------
   Field tables (frozen)
   ------------------------- */

/* entry.v1 : describes a single core/entry in the manifest */
static const can_field_t ENTRY_V1_FIELDS[] = {
    { "name",           0, CAN_TYPE_STRING, 1,  NULL }, /* canonical identifier for the core */
    { "path",           1, CAN_TYPE_STRING, 1,  NULL }, /* path relative to manifest root */
    { "type",           2, CAN_TYPE_STRING, 1,  NULL }, /* "file" | "dir" | "other" */
    { "size",           3, CAN_TYPE_U64,   0,  NULL }, /* bytes for files */
    { "mode",           4, CAN_TYPE_U32,   0,  NULL }, /* unix mode */
    { "mtime",          5, CAN_TYPE_I64,   0,  NULL }, /* epoch seconds (int64) */
    { "executable",     6, CAN_TYPE_BOOL,  0,  NULL }, /* true if exec bit or contains exec */
    { "elf",            7, CAN_TYPE_BOOL,  0,  NULL }  /* true if ELF magic present */
};

/* seed.manifest.v1 : top-level manifest describing discoveries */
static const can_field_t SEED_MANIFEST_V1_FIELDS[] = {
    { "schema_id",      0, CAN_TYPE_STRING, 1,  NULL }, /* "seed.manifest" */
    { "schema_ver",     1, CAN_TYPE_U32,   1,  NULL }, /* version number */
    { "generated_by",   2, CAN_TYPE_STRING, 0,  NULL }, /* optional agent id */
    { "generated_at",   3, CAN_TYPE_I64,   1,  NULL }, /* epoch seconds */
    { "total",          4, CAN_TYPE_U32,   1,  NULL }, /* total entries counted */
    { "functional",     5, CAN_TYPE_U32,   1,  NULL }, /* count */
    { "present_nonexec",6, CAN_TYPE_U32,   1,  NULL }, /* count */
    { "missing",        7, CAN_TYPE_U32,   1,  NULL }, /* count */
    { "entries",        8, CAN_TYPE_LIST,  0,  "entry.v1" } /* list of entry.v1 objects */
};

/* -------------------------
   Schema descriptors (frozen)
   ------------------------- */

static const can_schema_t SCHEMA_ENTRY_V1 = {
    .schema_name = "entry",
    .version = 1,
    .fields = ENTRY_V1_FIELDS,
    .field_count = sizeof(ENTRY_V1_FIELDS) / sizeof(ENTRY_V1_FIELDS[0])
};

static const can_schema_t SCHEMA_SEED_MANIFEST_V1 = {
    .schema_name = "seed.manifest",
    .version = 1,
    .fields = SEED_MANIFEST_V1_FIELDS,
    .field_count = sizeof(SEED_MANIFEST_V1_FIELDS) / sizeof(SEED_MANIFEST_V1_FIELDS[0])
};

/* Registry: list all known schemas here (append-only) */
static const can_schema_t * const SCHEMA_REGISTRY[] = {
    &SCHEMA_ENTRY_V1,
    &SCHEMA_SEED_MANIFEST_V1
};

/* Helper: compare schema name + version */
static int schema_matches(const can_schema_t *s, const char *name, uint16_t version) {
    if (!s || !name) return 0;
    if (strcmp(s->schema_name, name) != 0) return 0;
    return s->version == version;
}

/* -------------------------
   Public API
   ------------------------- */

const can_schema_t *can_schema_lookup(const char *name, uint16_t version) {
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof(SCHEMA_REGISTRY)/sizeof(SCHEMA_REGISTRY[0]); ++i) {
        const can_schema_t *s = SCHEMA_REGISTRY[i];
        if (schema_matches(s, name, version)) return s;
    }
    return NULL;
}

const can_schema_t *can_schema_lookup_latest(const char *name) {
    if (!name) return NULL;
    const can_schema_t *best = NULL;
    for (size_t i = 0; i < sizeof(SCHEMA_REGISTRY)/sizeof(SCHEMA_REGISTRY[0]); ++i) {
        const can_schema_t *s = SCHEMA_REGISTRY[i];
        if (strcmp(s->schema_name, name) != 0) continue;
        if (!best || s->version > best->version) best = s;
    }
    return best;
}

const can_field_t *can_schema_field_by_name(const can_schema_t *schema, const char *field_name) {
    if (!schema || !field_name) return NULL;
    for (size_t i = 0; i < schema->field_count; ++i) {
        if (strcmp(schema->fields[i].name, field_name) == 0) return &schema->fields[i];
    }
    return NULL;
}

const can_field_t *can_schema_field_by_id(const can_schema_t *schema, uint16_t id) {
    if (!schema) return NULL;
    for (size_t i = 0; i < schema->field_count; ++i) {
        if (schema->fields[i].id == id) return &schema->fields[i];
    }
    return NULL;
}

size_t can_schema_list_versions(const char *name, uint16_t *versions_out, size_t max_versions) {
    if (!name) return 0;
    /* collect versions into a small stack buffer (registry is tiny) */
    uint16_t tmp[16];
    size_t cnt = 0;
    for (size_t i = 0; i < sizeof(SCHEMA_REGISTRY)/sizeof(SCHEMA_REGISTRY[0]); ++i) {
        const can_schema_t *s = SCHEMA_REGISTRY[i];
        if (strcmp(s->schema_name, name) == 0) {
            if (cnt < sizeof(tmp)/sizeof(tmp[0])) tmp[cnt] = s->version;
            ++cnt;
        }
    }
    if (cnt == 0) return 0;
    /* sort ascending (simple bubble sort for tiny N) */
    for (size_t a = 0; a < cnt; ++a) {
        for (size_t b = a+1; b < cnt; ++b) {
            if (tmp[a] > tmp[b]) {
                uint16_t t = tmp[a];
                tmp[a] = tmp[b];
                tmp[b] = t;
            }
        }
    }
    /* copy up to max_versions */
    size_t to_copy = (max_versions < cnt) ? max_versions : cnt;
    for (size_t i = 0; i < to_copy; ++i) {
        versions_out[i] = tmp[i];
    }
    return cnt;
}
