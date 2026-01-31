// canonical/schema.h
#ifndef CANONICAL_SCHEMA_H
#define CANONICAL_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CAN_TYPE_BOOL,
    CAN_TYPE_U32,
    CAN_TYPE_U64,
    CAN_TYPE_I64,
    CAN_TYPE_STRING,
    CAN_TYPE_BYTES,
    CAN_TYPE_LIST,   // list of some element type (child_schema required)
    CAN_TYPE_OBJECT  // nested object (child_schema required)
} can_type_t;

typedef struct {
    const char *name;         // canonical field name (immutable)
    uint16_t id;              // stable field index (used for deterministic ordering)
    can_type_t type;          // primitive / container type
    int required;             // 1 = required, 0 = optional
    const char *child_schema; // if type is LIST or OBJECT, name of child schema (NULL otherwise)
} can_field_t;

typedef struct {
    const char *schema_name;  // e.g. "seed.manifest"
    uint16_t version;         // e.g. 1
    const can_field_t *fields;
    size_t field_count;
} can_schema_t;

/*
 * Lookup a schema by name + version.
 * Returns NULL if not found.
 */
const can_schema_t *can_schema_lookup(const char *name, uint16_t version);

/*
 * Find the latest version (highest version number) of a schema by name.
 * Returns NULL if no schema with that name exists.
 */
const can_schema_t *can_schema_lookup_latest(const char *name);

/*
 * Get a field descriptor by canonical field name.
 * Returns NULL if not found.
 */
const can_field_t *can_schema_field_by_name(const can_schema_t *schema, const char *field_name);

/*
 * Get a field descriptor by field id (index).
 * Returns NULL if not found.
 */
const can_field_t *can_schema_field_by_id(const can_schema_t *schema, uint16_t id);

/*
 * Utility: get the number of known schema versions for a name.
 * If versions_out != NULL, writes up to max_versions entries (ascending order).
 * Returns the total count available (may be > max_versions).
 */
size_t can_schema_list_versions(const char *name, uint16_t *versions_out, size_t max_versions);

#ifdef __cplusplus
}
#endif

#endif // CANONICAL_SCHEMA_H
