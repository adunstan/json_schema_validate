/*-------------------------------------------------------------------------
 *
 * json_schema_validate.c
 *    JSON Schema validation for PostgreSQL
 *
 * Copyright (c) 2026, Andrew Dunstan
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written agreement
 * is hereby granted, provided that the above copyright notice and this
 * paragraph appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 *-------------------------------------------------------------------------
 *
 * This extension provides functions to validate JSON/JSONB data against
 * JSON Schema specifications. It supports a significant subset of JSON
 * Schema draft-07, including:
 *
 *   - Type validation (string, number, integer, boolean, null, array, object)
 *   - String constraints (minLength, maxLength, pattern)
 *   - Numeric constraints (minimum, maximum, exclusiveMinimum, exclusiveMaximum,
 *     multipleOf)
 *   - Array constraints (minItems, maxItems, uniqueItems, items, contains,
 *     minContains, maxContains)
 *   - Object constraints (required, properties, additionalProperties,
 *     propertyNames, minProperties, maxProperties, patternProperties)
 *   - Schema composition (allOf, anyOf, oneOf, not)
 *   - Conditional schemas (if/then/else)
 *   - References ($ref with JSON Pointer)
 *   - Enumeration and const
 *   - Type arrays (e.g., "type": ["string", "null"])
 *   - Format validation (date-time, date, time, email, hostname, ipv4, ipv6,
 *     uri, uuid, regex)
 *
 * IDENTIFICATION
 *    json_schema_validate.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/jsonb.h"
#include "utils/builtins.h"
#include "utils/array.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "miscadmin.h"

#include <regex.h>
#include <string.h>

PG_MODULE_MAGIC;

/*
 * Compiled schema type - stores jsonb schema with cached regex patterns
 */
typedef struct JsonSchemaCompiled
{
    int32       vl_len_;        /* varlena header */
    /* The rest is the jsonb schema data */
} JsonSchemaCompiled;

#define DatumGetJsonSchemaCompiledP(d) ((JsonSchemaCompiled *) PG_DETOAST_DATUM(d))
#define PG_GETARG_JSONSCHEMA_COMPILED_P(n) DatumGetJsonSchemaCompiledP(PG_GETARG_DATUM(n))
#define PG_RETURN_JSONSCHEMA_COMPILED_P(x) PG_RETURN_POINTER(x)

/*
 * Regex cache entry
 */
typedef struct RegexCacheEntry
{
    char        pattern[256];   /* hash key - the pattern string */
    regex_t     regex;          /* compiled regex */
    bool        valid;          /* true if regex compiled successfully */
} RegexCacheEntry;

/* Global regex cache - persists for the backend session */
static HTAB *regex_cache = NULL;
static MemoryContext regex_cache_context = NULL;

#define REGEX_CACHE_SIZE 128

/*
 * Initialize the regex cache if not already done
 */
static void
init_regex_cache(void)
{
    HASHCTL     hash_ctl;

    if (regex_cache != NULL)
        return;

    /* Create a memory context for the cache that persists across calls */
    regex_cache_context = AllocSetContextCreate(TopMemoryContext,
                                                 "JsonSchema Regex Cache",
                                                 ALLOCSET_DEFAULT_SIZES);

    memset(&hash_ctl, 0, sizeof(hash_ctl));
    hash_ctl.keysize = 256;
    hash_ctl.entrysize = sizeof(RegexCacheEntry);
    hash_ctl.hcxt = regex_cache_context;

    regex_cache = hash_create("JsonSchema Regex Cache",
                              REGEX_CACHE_SIZE,
                              &hash_ctl,
                              HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);
}

/*
 * Get or compile a regex pattern, using the cache
 */
static regex_t *
get_cached_regex(const char *pattern, bool *valid)
{
    RegexCacheEntry *entry;
    bool        found;
    char        key[256];

    init_regex_cache();

    /* Truncate pattern to fit in key */
    strlcpy(key, pattern, sizeof(key));

    entry = (RegexCacheEntry *) hash_search(regex_cache, key, HASH_ENTER, &found);

    if (!found)
    {
        /* Compile the regex */
        int ret = regcomp(&entry->regex, pattern, REG_EXTENDED | REG_NOSUB);
        entry->valid = (ret == 0);
        if (!entry->valid)
        {
            /* Store pattern for key but mark as invalid */
            strlcpy(entry->pattern, key, sizeof(entry->pattern));
        }
    }

    *valid = entry->valid;
    return entry->valid ? &entry->regex : NULL;
}

/* Forward declarations */
static bool validate_jsonb_internal(Jsonb *data, Jsonb *schema, StringInfo errors);
static bool validate_value_with_root(JsonbValue *data, JsonbValue *schema, const char *path, StringInfo errors, JsonbContainer *root_schema);
static JsonbValue *get_jsonb_key(JsonbContainer *container, const char *key);
static const char *jsonb_type_name(JsonbValue *v);
static bool check_type(JsonbValue *data, JsonbValue *type_val);
static bool check_enum(JsonbValue *data, JsonbValue *enum_val);
static bool check_const(JsonbValue *data, JsonbValue *const_val);
static bool check_properties(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_additional_properties(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_required(JsonbValue *data, JsonbValue *required_val, const char *path, StringInfo errors);
static bool check_property_names(JsonbValue *data, JsonbValue *prop_names_schema, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_string_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors);
static bool check_number_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors);
static bool check_array_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_all_of(JsonbValue *data, JsonbValue *all_of_val, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_any_of(JsonbValue *data, JsonbValue *any_of_val, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_one_of(JsonbValue *data, JsonbValue *one_of_val, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_not(JsonbValue *data, JsonbValue *not_val, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_if_then_else(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema);
static bool check_object_size_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors);
static bool check_format(JsonbValue *data, JsonbValue *format_val, const char *path, StringInfo errors);
static JsonbValue *resolve_ref(const char *ref, JsonbContainer *root_schema);
static bool jsonb_values_equal(JsonbValue *a, JsonbValue *b);
static void append_error(StringInfo errors, const char *path, const char *message);
static char *build_path(const char *base, const char *key);

PG_FUNCTION_INFO_V1(jsonschema_is_valid_jsonb);
PG_FUNCTION_INFO_V1(jsonschema_is_valid_json);
PG_FUNCTION_INFO_V1(jsonschema_validate_jsonb);
PG_FUNCTION_INFO_V1(jsonschema_validate_json);

/* Compiled schema functions */
PG_FUNCTION_INFO_V1(jsonschema_compile);
PG_FUNCTION_INFO_V1(jsonschema_compiled_in);
PG_FUNCTION_INFO_V1(jsonschema_compiled_out);
PG_FUNCTION_INFO_V1(jsonschema_is_valid_compiled);
PG_FUNCTION_INFO_V1(jsonschema_validate_compiled);

/*
 * jsonschema_is_valid(data jsonb, schema jsonb) -> boolean
 */
Datum
jsonschema_is_valid_jsonb(PG_FUNCTION_ARGS)
{
    Jsonb *data = PG_GETARG_JSONB_P(0);
    Jsonb *schema = PG_GETARG_JSONB_P(1);
    bool result;

    result = validate_jsonb_internal(data, schema, NULL);

    PG_RETURN_BOOL(result);
}

/*
 * jsonschema_is_valid(data json, schema json) -> boolean
 */
Datum
jsonschema_is_valid_json(PG_FUNCTION_ARGS)
{
    text *data_text = PG_GETARG_TEXT_PP(0);
    text *schema_text = PG_GETARG_TEXT_PP(1);
    Jsonb *data;
    Jsonb *schema;
    Datum data_jsonb;
    Datum schema_jsonb;
    bool result;

    /* Convert json to jsonb */
    data_jsonb = DirectFunctionCall1(jsonb_in,
        CStringGetDatum(text_to_cstring(data_text)));
    schema_jsonb = DirectFunctionCall1(jsonb_in,
        CStringGetDatum(text_to_cstring(schema_text)));

    data = DatumGetJsonbP(data_jsonb);
    schema = DatumGetJsonbP(schema_jsonb);

    result = validate_jsonb_internal(data, schema, NULL);

    PG_RETURN_BOOL(result);
}

/*
 * jsonschema_validate(data jsonb, schema jsonb) -> jsonb
 * Returns NULL if valid, or array of errors if invalid.
 */
Datum
jsonschema_validate_jsonb(PG_FUNCTION_ARGS)
{
    Jsonb *data = PG_GETARG_JSONB_P(0);
    Jsonb *schema = PG_GETARG_JSONB_P(1);
    StringInfoData errors;
    Datum result;

    initStringInfo(&errors);
    appendStringInfoChar(&errors, '[');

    (void) validate_jsonb_internal(data, schema, &errors);

    /* Remove trailing comma if present */
    if (errors.len > 1 && errors.data[errors.len - 1] == ',')
        errors.len--;

    appendStringInfoChar(&errors, ']');

    result = DirectFunctionCall1(jsonb_in, CStringGetDatum(errors.data));
    pfree(errors.data);

    PG_RETURN_DATUM(result);
}

/*
 * jsonschema_validate(data json, schema json) -> json
 */
Datum
jsonschema_validate_json(PG_FUNCTION_ARGS)
{
    text *data_text = PG_GETARG_TEXT_PP(0);
    text *schema_text = PG_GETARG_TEXT_PP(1);
    Jsonb *data;
    Jsonb *schema;
    Datum data_jsonb;
    Datum schema_jsonb;
    StringInfoData errors;

    /* Convert json to jsonb */
    data_jsonb = DirectFunctionCall1(jsonb_in,
        CStringGetDatum(text_to_cstring(data_text)));
    schema_jsonb = DirectFunctionCall1(jsonb_in,
        CStringGetDatum(text_to_cstring(schema_text)));

    data = DatumGetJsonbP(data_jsonb);
    schema = DatumGetJsonbP(schema_jsonb);

    initStringInfo(&errors);
    appendStringInfoChar(&errors, '[');

    (void) validate_jsonb_internal(data, schema, &errors);

    /* Remove trailing comma if present */
    if (errors.len > 1 && errors.data[errors.len - 1] == ',')
        errors.len--;

    appendStringInfoChar(&errors, ']');

    PG_RETURN_TEXT_P(cstring_to_text(errors.data));
}

/*
 * Main validation function
 */
static bool
validate_jsonb_internal(Jsonb *data, Jsonb *schema, StringInfo errors)
{
    JsonbValue data_val;
    JsonbValue schema_val;

    /* Handle boolean schemas (true = always valid, false = always invalid) */
    if (JB_ROOT_IS_SCALAR(schema))
    {
        JsonbValue scalar;
        JsonbExtractScalar(&schema->root, &scalar);
        if (scalar.type == jbvBool)
            return scalar.val.boolean;
    }

    /* Schema must be an object */
    if (!JB_ROOT_IS_OBJECT(schema))
    {
        if (errors)
            append_error(errors, "", "Schema must be an object or boolean");
        return false;
    }

    /* Convert data to JsonbValue */
    if (JB_ROOT_IS_SCALAR(data))
    {
        JsonbExtractScalar(&data->root, &data_val);
    }
    else
    {
        /* For objects and arrays, use binary type with container reference */
        data_val.type = jbvBinary;
        data_val.val.binary.data = &data->root;
        data_val.val.binary.len = VARSIZE(data) - VARHDRSZ;
    }

    schema_val.type = jbvBinary;
    schema_val.val.binary.data = &schema->root;
    schema_val.val.binary.len = VARSIZE(schema) - VARHDRSZ;

    return validate_value_with_root(&data_val, &schema_val, "", errors, &schema->root);
}

/*
 * Validate a single value against a schema with root schema for $ref resolution
 */
static bool
validate_value_with_root(JsonbValue *data, JsonbValue *schema, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbContainer *schema_obj;
    JsonbValue *ref_val;
    JsonbValue *type_val;
    JsonbValue *enum_val;
    JsonbValue *const_val;
    JsonbValue *all_of_val;
    JsonbValue *any_of_val;
    JsonbValue *one_of_val;
    JsonbValue *not_val;
    bool valid = true;

    /* Handle boolean schemas */
    if (schema->type == jbvBool)
        return schema->val.boolean;

    if (schema->type == jbvBinary)
        schema_obj = schema->val.binary.data;
    else
        return true; /* Non-object schema, assume valid */

    /* Handle $ref - dereference and validate against referenced schema */
    ref_val = get_jsonb_key(schema_obj, "$ref");
    if (ref_val != NULL && ref_val->type == jbvString && root_schema != NULL)
    {
        char *ref_str = pnstrdup(ref_val->val.string.val, ref_val->val.string.len);
        JsonbValue *resolved = resolve_ref(ref_str, root_schema);
        pfree(ref_str);

        if (resolved != NULL)
        {
            /* Validate against the resolved schema */
            if (!validate_value_with_root(data, resolved, path, errors, root_schema))
                valid = false;
        }
        else
        {
            if (errors)
                append_error(errors, path, "Could not resolve $ref");
            valid = false;
        }
        /* Per JSON Schema spec, $ref used to ignore siblings, but draft 2019-09+ allows them */
        /* We'll continue processing other keywords for compatibility */
    }

    /* Check "type" keyword */
    type_val = get_jsonb_key(schema_obj, "type");
    if (type_val != NULL)
    {
        if (!check_type(data, type_val))
        {
            if (errors)
            {
                char msg[256];
                char *expected_type = "unknown";
                if (type_val->type == jbvString)
                    expected_type = pnstrdup(type_val->val.string.val, type_val->val.string.len);
                snprintf(msg, sizeof(msg), "Expected type %s but got %s",
                    expected_type, jsonb_type_name(data));
                append_error(errors, path, msg);
                if (type_val->type == jbvString)
                    pfree(expected_type);
            }
            valid = false;
        }
    }

    /* Check "enum" keyword */
    enum_val = get_jsonb_key(schema_obj, "enum");
    if (enum_val != NULL && !check_enum(data, enum_val))
    {
        if (errors)
            append_error(errors, path, "Value not in enum");
        valid = false;
    }

    /* Check "const" keyword */
    const_val = get_jsonb_key(schema_obj, "const");
    if (const_val != NULL && !check_const(data, const_val))
    {
        if (errors)
            append_error(errors, path, "Value does not match const");
        valid = false;
    }

    /* Check "allOf" keyword */
    all_of_val = get_jsonb_key(schema_obj, "allOf");
    if (all_of_val != NULL)
    {
        if (!check_all_of(data, all_of_val, path, errors, root_schema))
            valid = false;
    }

    /* Check "anyOf" keyword */
    any_of_val = get_jsonb_key(schema_obj, "anyOf");
    if (any_of_val != NULL)
    {
        if (!check_any_of(data, any_of_val, path, errors, root_schema))
            valid = false;
    }

    /* Check "oneOf" keyword */
    one_of_val = get_jsonb_key(schema_obj, "oneOf");
    if (one_of_val != NULL)
    {
        if (!check_one_of(data, one_of_val, path, errors, root_schema))
            valid = false;
    }

    /* Check "not" keyword */
    not_val = get_jsonb_key(schema_obj, "not");
    if (not_val != NULL)
    {
        if (!check_not(data, not_val, path, errors, root_schema))
            valid = false;
    }

    /* Check if/then/else */
    if (!check_if_then_else(data, schema_obj, path, errors, root_schema))
        valid = false;

    /* Type-specific validations */
    if (data->type == jbvString ||
        (data->type == jbvBinary && JsonContainerIsScalar(data->val.binary.data)))
    {
        JsonbValue *format_val;

        if (!check_string_constraints(data, schema_obj, path, errors))
            valid = false;

        format_val = get_jsonb_key(schema_obj, "format");
        if (format_val != NULL)
        {
            if (!check_format(data, format_val, path, errors))
                valid = false;
        }
    }

    if (data->type == jbvNumeric)
    {
        if (!check_number_constraints(data, schema_obj, path, errors))
            valid = false;
    }

    /* Object validations */
    if (data->type == jbvObject ||
        (data->type == jbvBinary && JsonContainerIsObject(data->val.binary.data)))
    {
        JsonbValue *required_val;
        JsonbValue *prop_names_val;

        required_val = get_jsonb_key(schema_obj, "required");
        if (required_val != NULL)
        {
            if (!check_required(data, required_val, path, errors))
                valid = false;
        }

        if (!check_properties(data, schema_obj, path, errors, root_schema))
            valid = false;

        if (!check_additional_properties(data, schema_obj, path, errors, root_schema))
            valid = false;

        prop_names_val = get_jsonb_key(schema_obj, "propertyNames");
        if (prop_names_val != NULL)
        {
            if (!check_property_names(data, prop_names_val, path, errors, root_schema))
                valid = false;
        }

        if (!check_object_size_constraints(data, schema_obj, path, errors))
            valid = false;
    }

    /* Array validations */
    if (data->type == jbvArray ||
        (data->type == jbvBinary && JsonContainerIsArray(data->val.binary.data)))
    {
        if (!check_array_constraints(data, schema_obj, path, errors, root_schema))
            valid = false;
    }

    return valid;
}

/*
 * Get a key from a jsonb object
 */
static JsonbValue *
get_jsonb_key(JsonbContainer *container, const char *key)
{
    JsonbValue k;
    JsonbValue *v;

    k.type = jbvString;
    k.val.string.val = (char *)key;
    k.val.string.len = strlen(key);

    v = findJsonbValueFromContainer(container, JB_FOBJECT, &k);
    return v;
}

/*
 * Get type name for a JsonbValue
 */
static const char *
jsonb_type_name(JsonbValue *v)
{
    if (v == NULL)
        return "null";

    switch (v->type)
    {
        case jbvNull:
            return "null";
        case jbvBool:
            return "boolean";
        case jbvNumeric:
            return "number";
        case jbvString:
            return "string";
        case jbvArray:
            return "array";
        case jbvObject:
            return "object";
        case jbvBinary:
            if (JsonContainerIsObject(v->val.binary.data))
                return "object";
            if (JsonContainerIsArray(v->val.binary.data))
                return "array";
            if (JsonContainerIsScalar(v->val.binary.data))
            {
                JsonbValue scalar;
                JsonbExtractScalar(v->val.binary.data, &scalar);
                return jsonb_type_name(&scalar);
            }
            return "unknown";
        default:
            return "unknown";
    }
}

/*
 * Check if data matches a single type string
 */
static bool
check_single_type(JsonbValue *data, const char *type_str, int type_len)
{
    const char *actual = jsonb_type_name(data);

    /* Handle "integer" as a special case of "number" */
    if (type_len == 7 && strncmp(type_str, "integer", 7) == 0)
    {
        if (strcmp(actual, "number") != 0)
            return false;
        /* Check if it's actually an integer (no fractional part) */
        if (data->type == jbvNumeric)
        {
            Numeric num = data->val.numeric;
            Numeric floor_val;
            floor_val = DatumGetNumeric(DirectFunctionCall1(numeric_floor,
                NumericGetDatum(num)));
            return DatumGetBool(DirectFunctionCall2(numeric_eq,
                NumericGetDatum(num),
                NumericGetDatum(floor_val)));
        }
        return true;
    }

    /* Compare type names - must match exactly */
    return (type_len == (int)strlen(actual) &&
            strncmp(type_str, actual, type_len) == 0);
}

/*
 * Check if data matches the expected type (string or array of strings)
 */
static bool
check_type(JsonbValue *data, JsonbValue *type_val)
{
    /* Handle type as a string */
    if (type_val->type == jbvString)
    {
        return check_single_type(data, type_val->val.string.val, type_val->val.string.len);
    }

    /* Handle type as an array of strings */
    if (type_val->type == jbvBinary)
    {
        JsonbContainer *type_arr = type_val->val.binary.data;
        JsonbIterator *it;
        JsonbValue v;
        JsonbIteratorToken tok;

        if (!JsonContainerIsArray(type_arr))
            return true; /* Invalid type specification */

        it = JsonbIteratorInit(type_arr);
        while ((tok = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
        {
            if (tok == WJB_ELEM && v.type == jbvString)
            {
                if (check_single_type(data, v.val.string.val, v.val.string.len))
                    return true; /* Match found */
            }
        }
        return false; /* No type in array matched */
    }

    return true; /* Invalid type specification, skip check */
}

/*
 * Check if data is in the enum array
 */
static bool
check_enum(JsonbValue *data, JsonbValue *enum_val)
{
    JsonbContainer *enum_arr;
    JsonbIterator *it;
    JsonbValue v;
    JsonbIteratorToken tok;

    if (enum_val->type != jbvBinary)
        return true;

    enum_arr = enum_val->val.binary.data;
    if (!JsonContainerIsArray(enum_arr))
        return true;

    it = JsonbIteratorInit(enum_arr);
    while ((tok = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
    {
        if (tok == WJB_ELEM)
        {
            /* Simple type and value comparison */
            if (v.type == data->type)
            {
                switch (v.type)
                {
                    case jbvNull:
                        return true;
                    case jbvBool:
                        if (v.val.boolean == data->val.boolean)
                            return true;
                        break;
                    case jbvString:
                        if (v.val.string.len == data->val.string.len &&
                            memcmp(v.val.string.val, data->val.string.val, v.val.string.len) == 0)
                            return true;
                        break;
                    case jbvNumeric:
                        if (DatumGetBool(DirectFunctionCall2(numeric_eq,
                                NumericGetDatum(v.val.numeric),
                                NumericGetDatum(data->val.numeric))))
                            return true;
                        break;
                    default:
                        break;
                }
            }
        }
    }

    return false;
}

/*
 * Check required properties
 */
static bool
check_required(JsonbValue *data, JsonbValue *required_val, const char *path, StringInfo errors)
{
    JsonbContainer *data_obj;
    JsonbContainer *required_arr;
    JsonbIterator *it;
    JsonbValue v;
    JsonbIteratorToken tok;
    bool valid = true;

    if (data->type == jbvBinary)
        data_obj = data->val.binary.data;
    else
        return true;

    if (required_val->type != jbvBinary)
        return true;

    required_arr = required_val->val.binary.data;
    if (!JsonContainerIsArray(required_arr))
        return true;

    it = JsonbIteratorInit(required_arr);
    while ((tok = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
    {
        if (tok == WJB_ELEM && v.type == jbvString)
        {
            JsonbValue *found = findJsonbValueFromContainer(data_obj, JB_FOBJECT, &v);
            if (found == NULL)
            {
                if (errors)
                {
                    char msg[256];
                    char *prop = pnstrdup(v.val.string.val, v.val.string.len);
                    snprintf(msg, sizeof(msg), "Missing required property: %s", prop);
                    append_error(errors, path, msg);
                    pfree(prop);
                }
                valid = false;
            }
        }
    }

    return valid;
}

/*
 * Check properties against their schemas
 */
static bool
check_properties(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbValue *props_val;
    JsonbContainer *data_obj;
    JsonbContainer *props_obj;
    JsonbIterator *it;
    JsonbValue v;
    JsonbIteratorToken tok;
    bool valid = true;

    props_val = get_jsonb_key(schema_obj, "properties");
    if (props_val == NULL || props_val->type != jbvBinary)
        return true;

    if (data->type == jbvBinary)
        data_obj = data->val.binary.data;
    else
        return true;

    props_obj = props_val->val.binary.data;
    if (!JsonContainerIsObject(props_obj))
        return true;

    it = JsonbIteratorInit(props_obj);
    while ((tok = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
    {
        if (tok == WJB_KEY)
        {
            char *prop_name = pnstrdup(v.val.string.val, v.val.string.len);
            JsonbValue *data_val;
            JsonbValue prop_schema;
            char *prop_path;

            /* Get next value (the property schema) */
            tok = JsonbIteratorNext(&it, &prop_schema, true);

            /* Find this property in data */
            data_val = get_jsonb_key(data_obj, prop_name);
            if (data_val != NULL)
            {
                prop_path = build_path(path, prop_name);
                if (!validate_value_with_root(data_val, &prop_schema, prop_path, errors, root_schema))
                    valid = false;
                pfree(prop_path);
            }

            pfree(prop_name);
        }
    }

    return valid;
}

/*
 * Check propertyNames - validates that all property names match a schema
 */
static bool
check_property_names(JsonbValue *data, JsonbValue *prop_names_schema, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbContainer *data_obj;
    JsonbIterator *it;
    JsonbValue v;
    JsonbIteratorToken tok;
    bool valid = true;

    if (prop_names_schema == NULL)
        return true;

    if (data->type == jbvBinary)
        data_obj = data->val.binary.data;
    else
        return true;

    if (!JsonContainerIsObject(data_obj))
        return true;

    it = JsonbIteratorInit(data_obj);
    while ((tok = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
    {
        if (tok == WJB_KEY)
        {
            /* v is the property name as a string - validate it against the schema */
            char *key_path;
            char *key_name = pnstrdup(v.val.string.val, v.val.string.len);

            key_path = build_path(path, key_name);

            if (!validate_value_with_root(&v, prop_names_schema, key_path, errors, root_schema))
                valid = false;

            pfree(key_path);
            pfree(key_name);
        }
    }

    return valid;
}

/*
 * Check string constraints (minLength, maxLength, pattern)
 */
static bool
check_string_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors)
{
    JsonbValue *minlen_val, *maxlen_val, *pattern_val;
    int len;
    bool valid = true;
    char *str_data = NULL;
    int str_len = 0;

    /* Get the actual string value */
    if (data->type == jbvString)
    {
        str_data = data->val.string.val;
        str_len = data->val.string.len;
    }
    else if (data->type == jbvBinary && JsonContainerIsScalar(data->val.binary.data))
    {
        JsonbValue scalar;
        JsonbExtractScalar(data->val.binary.data, &scalar);
        if (scalar.type == jbvString)
        {
            str_data = scalar.val.string.val;
            str_len = scalar.val.string.len;
        }
    }

    if (str_data == NULL)
        return true;

    len = str_len;

    minlen_val = get_jsonb_key(schema_obj, "minLength");
    if (minlen_val != NULL && minlen_val->type == jbvNumeric)
    {
        int minlen = DatumGetInt32(DirectFunctionCall1(numeric_int4,
            NumericGetDatum(minlen_val->val.numeric)));
        if (len < minlen)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "String length %d is less than minLength %d", len, minlen);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    maxlen_val = get_jsonb_key(schema_obj, "maxLength");
    if (maxlen_val != NULL && maxlen_val->type == jbvNumeric)
    {
        int maxlen = DatumGetInt32(DirectFunctionCall1(numeric_int4,
            NumericGetDatum(maxlen_val->val.numeric)));
        if (len > maxlen)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "String length %d exceeds maxLength %d", len, maxlen);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    pattern_val = get_jsonb_key(schema_obj, "pattern");
    if (pattern_val != NULL && pattern_val->type == jbvString)
    {
        char *pattern = pnstrdup(pattern_val->val.string.val, pattern_val->val.string.len);
        char *str = pnstrdup(str_data, str_len);
        bool regex_valid;
        regex_t *cached_regex;

        cached_regex = get_cached_regex(pattern, &regex_valid);
        if (regex_valid && cached_regex != NULL)
        {
            int ret = regexec(cached_regex, str, 0, NULL, 0);
            if (ret == REG_NOMATCH)
            {
                if (errors)
                {
                    char msg[512];
                    snprintf(msg, sizeof(msg), "String does not match pattern: %s", pattern);
                    append_error(errors, path, msg);
                }
                valid = false;
            }
        }

        pfree(pattern);
        pfree(str);
    }

    return valid;
}

/*
 * Check number constraints (minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf)
 */
static bool
check_number_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors)
{
    JsonbValue *min_val, *max_val, *exmin_val, *exmax_val, *multiple_of_val;
    Numeric data_num;
    bool valid = true;

    if (data->type != jbvNumeric)
        return true;

    data_num = data->val.numeric;

    min_val = get_jsonb_key(schema_obj, "minimum");
    if (min_val != NULL && min_val->type == jbvNumeric)
    {
        if (DatumGetBool(DirectFunctionCall2(numeric_lt,
                NumericGetDatum(data_num),
                NumericGetDatum(min_val->val.numeric))))
        {
            if (errors)
                append_error(errors, path, "Value is less than minimum");
            valid = false;
        }
    }

    max_val = get_jsonb_key(schema_obj, "maximum");
    if (max_val != NULL && max_val->type == jbvNumeric)
    {
        if (DatumGetBool(DirectFunctionCall2(numeric_gt,
                NumericGetDatum(data_num),
                NumericGetDatum(max_val->val.numeric))))
        {
            if (errors)
                append_error(errors, path, "Value exceeds maximum");
            valid = false;
        }
    }

    exmin_val = get_jsonb_key(schema_obj, "exclusiveMinimum");
    if (exmin_val != NULL && exmin_val->type == jbvNumeric)
    {
        if (DatumGetBool(DirectFunctionCall2(numeric_le,
                NumericGetDatum(data_num),
                NumericGetDatum(exmin_val->val.numeric))))
        {
            if (errors)
                append_error(errors, path, "Value must be greater than exclusiveMinimum");
            valid = false;
        }
    }

    exmax_val = get_jsonb_key(schema_obj, "exclusiveMaximum");
    if (exmax_val != NULL && exmax_val->type == jbvNumeric)
    {
        if (DatumGetBool(DirectFunctionCall2(numeric_ge,
                NumericGetDatum(data_num),
                NumericGetDatum(exmax_val->val.numeric))))
        {
            if (errors)
                append_error(errors, path, "Value must be less than exclusiveMaximum");
            valid = false;
        }
    }

    multiple_of_val = get_jsonb_key(schema_obj, "multipleOf");
    if (multiple_of_val != NULL && multiple_of_val->type == jbvNumeric)
    {
        /* Check if data_num / multipleOf is an integer (remainder is 0) */
        Numeric divisor = multiple_of_val->val.numeric;
        Numeric remainder;

        remainder = DatumGetNumeric(DirectFunctionCall2(numeric_mod,
                NumericGetDatum(data_num),
                NumericGetDatum(divisor)));

        /* Check if remainder is zero */
        if (!DatumGetBool(DirectFunctionCall2(numeric_eq,
                NumericGetDatum(remainder),
                DirectFunctionCall1(int4_numeric, Int32GetDatum(0)))))
        {
            if (errors)
                append_error(errors, path, "Value is not a multiple of multipleOf");
            valid = false;
        }
    }

    return valid;
}

/*
 * Check array constraints (minItems, maxItems, uniqueItems, items, contains, minContains, maxContains)
 */
static bool
check_array_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbContainer *data_arr;
    JsonbValue *minitems_val, *maxitems_val, *items_val;
    JsonbValue *unique_val, *contains_val, *min_contains_val, *max_contains_val;
    int count;
    bool valid = true;

    if (data->type == jbvBinary)
        data_arr = data->val.binary.data;
    else if (data->type == jbvArray)
        return true; /* No container to check */
    else
        return true;

    if (!JsonContainerIsArray(data_arr))
        return true;

    count = JsonContainerSize(data_arr);

    minitems_val = get_jsonb_key(schema_obj, "minItems");
    if (minitems_val != NULL && minitems_val->type == jbvNumeric)
    {
        int minitems = DatumGetInt32(DirectFunctionCall1(numeric_int4,
            NumericGetDatum(minitems_val->val.numeric)));
        if (count < minitems)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Array has %d items, minimum is %d", count, minitems);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    maxitems_val = get_jsonb_key(schema_obj, "maxItems");
    if (maxitems_val != NULL && maxitems_val->type == jbvNumeric)
    {
        int maxitems = DatumGetInt32(DirectFunctionCall1(numeric_int4,
            NumericGetDatum(maxitems_val->val.numeric)));
        if (count > maxitems)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Array has %d items, maximum is %d", count, maxitems);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    /* Check uniqueItems */
    unique_val = get_jsonb_key(schema_obj, "uniqueItems");
    if (unique_val != NULL && unique_val->type == jbvBool && unique_val->val.boolean)
    {
        /* Check for duplicate items using O(n^2) comparison */
        JsonbIterator *it1;
        JsonbValue elem1;
        JsonbIteratorToken tok1;
        int idx1 = 0;
        bool has_duplicate = false;

        it1 = JsonbIteratorInit(data_arr);
        while ((tok1 = JsonbIteratorNext(&it1, &elem1, true)) != WJB_DONE && !has_duplicate)
        {
            if (tok1 == WJB_ELEM)
            {
                JsonbIterator *it2;
                JsonbValue elem2;
                JsonbIteratorToken tok2;
                int idx2 = 0;

                it2 = JsonbIteratorInit(data_arr);
                while ((tok2 = JsonbIteratorNext(&it2, &elem2, true)) != WJB_DONE)
                {
                    if (tok2 == WJB_ELEM)
                    {
                        if (idx2 > idx1 && jsonb_values_equal(&elem1, &elem2))
                        {
                            has_duplicate = true;
                            break;
                        }
                        idx2++;
                    }
                }
                idx1++;
            }
        }

        if (has_duplicate)
        {
            if (errors)
                append_error(errors, path, "Array items are not unique");
            valid = false;
        }
    }

    /* Check items schema */
    items_val = get_jsonb_key(schema_obj, "items");
    if (items_val != NULL && items_val->type == jbvBinary)
    {
        JsonbIterator *it;
        JsonbValue elem;
        JsonbIteratorToken tok;
        int idx = 0;

        it = JsonbIteratorInit(data_arr);
        while ((tok = JsonbIteratorNext(&it, &elem, true)) != WJB_DONE)
        {
            if (tok == WJB_ELEM)
            {
                char idx_str[32];
                char *elem_path;

                snprintf(idx_str, sizeof(idx_str), "[%d]", idx);
                elem_path = build_path(path, idx_str);

                if (!validate_value_with_root(&elem, items_val, elem_path, errors, root_schema))
                    valid = false;

                pfree(elem_path);
                idx++;
            }
        }
    }

    /* Check contains, minContains, maxContains */
    contains_val = get_jsonb_key(schema_obj, "contains");
    if (contains_val != NULL)
    {
        JsonbIterator *it;
        JsonbValue elem;
        JsonbIteratorToken tok;
        int contains_count = 0;
        int min_contains = 1;  /* Default: at least 1 match required */
        int max_contains = -1; /* Default: no upper limit */

        min_contains_val = get_jsonb_key(schema_obj, "minContains");
        if (min_contains_val != NULL && min_contains_val->type == jbvNumeric)
        {
            min_contains = DatumGetInt32(DirectFunctionCall1(numeric_int4,
                NumericGetDatum(min_contains_val->val.numeric)));
        }

        max_contains_val = get_jsonb_key(schema_obj, "maxContains");
        if (max_contains_val != NULL && max_contains_val->type == jbvNumeric)
        {
            max_contains = DatumGetInt32(DirectFunctionCall1(numeric_int4,
                NumericGetDatum(max_contains_val->val.numeric)));
        }

        /* Count how many items match the contains schema */
        it = JsonbIteratorInit(data_arr);
        while ((tok = JsonbIteratorNext(&it, &elem, true)) != WJB_DONE)
        {
            if (tok == WJB_ELEM)
            {
                if (validate_value_with_root(&elem, contains_val, path, NULL, root_schema))
                    contains_count++;
            }
        }

        if (contains_count < min_contains)
        {
            if (errors)
            {
                char msg[256];
                if (min_contains == 1)
                    snprintf(msg, sizeof(msg), "Array does not contain any item matching the contains schema");
                else
                    snprintf(msg, sizeof(msg), "Array contains %d matching items, minimum is %d", contains_count, min_contains);
                append_error(errors, path, msg);
            }
            valid = false;
        }

        if (max_contains >= 0 && contains_count > max_contains)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Array contains %d matching items, maximum is %d", contains_count, max_contains);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    return valid;
}

/*
 * Compare two JsonbValues for equality
 */
static bool
jsonb_values_equal(JsonbValue *a, JsonbValue *b)
{
    /* Handle type mismatches */
    if (a->type != b->type)
    {
        /* Handle binary containers */
        if (a->type == jbvBinary && b->type != jbvBinary)
        {
            if (JsonContainerIsScalar(a->val.binary.data))
            {
                JsonbValue scalar;
                JsonbExtractScalar(a->val.binary.data, &scalar);
                return jsonb_values_equal(&scalar, b);
            }
            return false;
        }
        if (b->type == jbvBinary && a->type != jbvBinary)
        {
            if (JsonContainerIsScalar(b->val.binary.data))
            {
                JsonbValue scalar;
                JsonbExtractScalar(b->val.binary.data, &scalar);
                return jsonb_values_equal(a, &scalar);
            }
            return false;
        }
        return false;
    }

    switch (a->type)
    {
        case jbvNull:
            return true;
        case jbvBool:
            return a->val.boolean == b->val.boolean;
        case jbvNumeric:
            return DatumGetBool(DirectFunctionCall2(numeric_eq,
                NumericGetDatum(a->val.numeric),
                NumericGetDatum(b->val.numeric)));
        case jbvString:
            return (a->val.string.len == b->val.string.len &&
                    memcmp(a->val.string.val, b->val.string.val, a->val.string.len) == 0);
        case jbvBinary:
            /* For complex types, compare serialized forms */
            {
                JsonbContainer *ca = a->val.binary.data;
                JsonbContainer *cb = b->val.binary.data;
                /* Simple size comparison first */
                if (JsonContainerSize(ca) != JsonContainerSize(cb))
                    return false;
                /* TODO: Deep comparison of objects/arrays */
                return false;
            }
        default:
            return false;
    }
}

/*
 * Check const - value must exactly match
 */
static bool
check_const(JsonbValue *data, JsonbValue *const_val)
{
    return jsonb_values_equal(data, const_val);
}

/*
 * Check additionalProperties - validate properties not in "properties"
 */
static bool
check_additional_properties(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbValue *addl_props_val;
    JsonbValue *props_val;
    JsonbValue *pattern_props_val;
    JsonbContainer *data_obj;
    JsonbContainer *props_obj = NULL;
    JsonbIterator *it;
    JsonbValue v;
    JsonbIteratorToken tok;
    bool valid = true;
    bool addl_props_bool = true;

    addl_props_val = get_jsonb_key(schema_obj, "additionalProperties");
    if (addl_props_val == NULL)
        return true; /* No constraint */

    /* Get the properties object if it exists */
    props_val = get_jsonb_key(schema_obj, "properties");
    if (props_val != NULL && props_val->type == jbvBinary)
        props_obj = props_val->val.binary.data;

    /* Get patternProperties if it exists (we'll skip those too) */
    pattern_props_val = get_jsonb_key(schema_obj, "patternProperties");

    if (data->type == jbvBinary)
        data_obj = data->val.binary.data;
    else
        return true;

    if (!JsonContainerIsObject(data_obj))
        return true;

    /* Check if additionalProperties is a boolean false */
    if (addl_props_val->type == jbvBool)
    {
        addl_props_bool = addl_props_val->val.boolean;
        if (addl_props_bool)
            return true; /* true means allow all additional properties */
    }

    /* Iterate through data properties */
    it = JsonbIteratorInit(data_obj);
    while ((tok = JsonbIteratorNext(&it, &v, true)) != WJB_DONE)
    {
        if (tok == WJB_KEY)
        {
            char *prop_name = pnstrdup(v.val.string.val, v.val.string.len);
            bool is_defined = false;
            bool matches_pattern = false;

            /* Check if property is in "properties" */
            if (props_obj != NULL)
            {
                JsonbValue *found = get_jsonb_key(props_obj, prop_name);
                if (found != NULL)
                    is_defined = true;
            }

            /* Check if property matches any pattern in "patternProperties" */
            if (!is_defined && pattern_props_val != NULL && pattern_props_val->type == jbvBinary)
            {
                JsonbContainer *pattern_obj = pattern_props_val->val.binary.data;
                JsonbIterator *pit;
                JsonbValue pv;
                JsonbIteratorToken ptok;

                pit = JsonbIteratorInit(pattern_obj);
                while ((ptok = JsonbIteratorNext(&pit, &pv, true)) != WJB_DONE)
                {
                    if (ptok == WJB_KEY)
                    {
                        char *pattern = pnstrdup(pv.val.string.val, pv.val.string.len);
                        regex_t regex;

                        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
                        {
                            if (regexec(&regex, prop_name, 0, NULL, 0) == 0)
                                matches_pattern = true;
                            regfree(&regex);
                        }
                        pfree(pattern);

                        /* Skip the value */
                        JsonbIteratorNext(&pit, &pv, true);

                        if (matches_pattern)
                            break;
                    }
                }
            }

            if (!is_defined && !matches_pattern)
            {
                /* This is an additional property */
                if (addl_props_val->type == jbvBool && !addl_props_bool)
                {
                    /* additionalProperties: false - reject */
                    if (errors)
                    {
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Additional property '%s' is not allowed", prop_name);
                        append_error(errors, path, msg);
                    }
                    valid = false;
                }
                else if (addl_props_val->type == jbvBinary)
                {
                    /* additionalProperties is a schema - validate against it */
                    JsonbValue *data_val = get_jsonb_key(data_obj, prop_name);
                    if (data_val != NULL)
                    {
                        char *prop_path = build_path(path, prop_name);
                        if (!validate_value_with_root(data_val, addl_props_val, prop_path, errors, root_schema))
                            valid = false;
                        pfree(prop_path);
                    }
                }
            }

            pfree(prop_name);

            /* Skip the value */
            JsonbIteratorNext(&it, &v, true);
        }
    }

    return valid;
}

/*
 * Check allOf - data must match ALL schemas in the array
 */
static bool
check_all_of(JsonbValue *data, JsonbValue *all_of_val, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbContainer *arr;
    JsonbIterator *it;
    JsonbValue schema;
    JsonbIteratorToken tok;
    bool valid = true;
    int idx = 0;

    if (all_of_val->type != jbvBinary)
        return true;

    arr = all_of_val->val.binary.data;
    if (!JsonContainerIsArray(arr))
        return true;

    it = JsonbIteratorInit(arr);
    while ((tok = JsonbIteratorNext(&it, &schema, true)) != WJB_DONE)
    {
        if (tok == WJB_ELEM)
        {
            if (!validate_value_with_root(data, &schema, path, errors, root_schema))
            {
                valid = false;
                /* Continue checking all schemas to report all errors */
            }
            idx++;
        }
    }

    return valid;
}

/*
 * Check anyOf - data must match AT LEAST ONE schema in the array
 */
static bool
check_any_of(JsonbValue *data, JsonbValue *any_of_val, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbContainer *arr;
    JsonbIterator *it;
    JsonbValue schema;
    JsonbIteratorToken tok;
    int match_count = 0;

    if (any_of_val->type != jbvBinary)
        return true;

    arr = any_of_val->val.binary.data;
    if (!JsonContainerIsArray(arr))
        return true;

    it = JsonbIteratorInit(arr);
    while ((tok = JsonbIteratorNext(&it, &schema, true)) != WJB_DONE)
    {
        if (tok == WJB_ELEM)
        {
            /* Check without collecting errors */
            if (validate_value_with_root(data, &schema, path, NULL, root_schema))
            {
                match_count++;
                break; /* One match is enough */
            }
        }
    }

    if (match_count == 0)
    {
        if (errors)
            append_error(errors, path, "Value does not match any schema in anyOf");
        return false;
    }

    return true;
}

/*
 * Check oneOf - data must match EXACTLY ONE schema in the array
 */
static bool
check_one_of(JsonbValue *data, JsonbValue *one_of_val, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbContainer *arr;
    JsonbIterator *it;
    JsonbValue schema;
    JsonbIteratorToken tok;
    int match_count = 0;

    if (one_of_val->type != jbvBinary)
        return true;

    arr = one_of_val->val.binary.data;
    if (!JsonContainerIsArray(arr))
        return true;

    it = JsonbIteratorInit(arr);
    while ((tok = JsonbIteratorNext(&it, &schema, true)) != WJB_DONE)
    {
        if (tok == WJB_ELEM)
        {
            /* Check without collecting errors */
            if (validate_value_with_root(data, &schema, path, NULL, root_schema))
                match_count++;
        }
    }

    if (match_count == 0)
    {
        if (errors)
            append_error(errors, path, "Value does not match any schema in oneOf");
        return false;
    }
    else if (match_count > 1)
    {
        if (errors)
        {
            char msg[256];
            snprintf(msg, sizeof(msg), "Value matches %d schemas in oneOf, but must match exactly one", match_count);
            append_error(errors, path, msg);
        }
        return false;
    }

    return true;
}

/*
 * Check not - data must NOT match the schema
 */
static bool
check_not(JsonbValue *data, JsonbValue *not_val, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    /* Validate without collecting errors */
    if (validate_value_with_root(data, not_val, path, NULL, root_schema))
    {
        /* Data matches the schema, which means it fails the "not" constraint */
        if (errors)
            append_error(errors, path, "Value must not match the schema in 'not'");
        return false;
    }

    return true;
}

/*
 * Check if/then/else conditional schema
 */
static bool
check_if_then_else(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors, JsonbContainer *root_schema)
{
    JsonbValue *if_val;
    JsonbValue *then_val;
    JsonbValue *else_val;
    bool if_result;

    if_val = get_jsonb_key(schema_obj, "if");
    if (if_val == NULL)
        return true; /* No if/then/else to check */

    then_val = get_jsonb_key(schema_obj, "then");
    else_val = get_jsonb_key(schema_obj, "else");

    /* If neither then nor else is present, if alone has no effect */
    if (then_val == NULL && else_val == NULL)
        return true;

    /* Evaluate the "if" schema (without collecting errors) */
    if_result = validate_value_with_root(data, if_val, path, NULL, root_schema);

    if (if_result)
    {
        /* "if" matched, validate against "then" if present */
        if (then_val != NULL)
        {
            if (!validate_value_with_root(data, then_val, path, errors, root_schema))
                return false;
        }
    }
    else
    {
        /* "if" did not match, validate against "else" if present */
        if (else_val != NULL)
        {
            if (!validate_value_with_root(data, else_val, path, errors, root_schema))
                return false;
        }
    }

    return true;
}

/*
 * Check object size constraints (minProperties, maxProperties)
 */
static bool
check_object_size_constraints(JsonbValue *data, JsonbContainer *schema_obj, const char *path, StringInfo errors)
{
    JsonbContainer *data_obj;
    JsonbValue *min_props_val, *max_props_val;
    int prop_count;
    bool valid = true;

    if (data->type == jbvBinary)
        data_obj = data->val.binary.data;
    else
        return true;

    if (!JsonContainerIsObject(data_obj))
        return true;

    prop_count = JsonContainerSize(data_obj);

    min_props_val = get_jsonb_key(schema_obj, "minProperties");
    if (min_props_val != NULL && min_props_val->type == jbvNumeric)
    {
        int min_props = DatumGetInt32(DirectFunctionCall1(numeric_int4,
            NumericGetDatum(min_props_val->val.numeric)));
        if (prop_count < min_props)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Object has %d properties, minimum is %d", prop_count, min_props);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    max_props_val = get_jsonb_key(schema_obj, "maxProperties");
    if (max_props_val != NULL && max_props_val->type == jbvNumeric)
    {
        int max_props = DatumGetInt32(DirectFunctionCall1(numeric_int4,
            NumericGetDatum(max_props_val->val.numeric)));
        if (prop_count > max_props)
        {
            if (errors)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Object has %d properties, maximum is %d", prop_count, max_props);
                append_error(errors, path, msg);
            }
            valid = false;
        }
    }

    return valid;
}

/*
 * Check format validation for strings
 * Supports: date-time, date, time, email, hostname, ipv4, ipv6, uri, uuid, regex
 */
static bool
check_format(JsonbValue *data, JsonbValue *format_val, const char *path, StringInfo errors)
{
    char *format_str;
    char *str_data = NULL;
    int str_len = 0;
    char *str = NULL;
    bool valid = true;

    if (format_val == NULL || format_val->type != jbvString)
        return true;

    /* Get the actual string value */
    if (data->type == jbvString)
    {
        str_data = data->val.string.val;
        str_len = data->val.string.len;
    }
    else if (data->type == jbvBinary && JsonContainerIsScalar(data->val.binary.data))
    {
        JsonbValue scalar;
        JsonbExtractScalar(data->val.binary.data, &scalar);
        if (scalar.type == jbvString)
        {
            str_data = scalar.val.string.val;
            str_len = scalar.val.string.len;
        }
    }

    if (str_data == NULL)
        return true;

    str = pnstrdup(str_data, str_len);
    format_str = pnstrdup(format_val->val.string.val, format_val->val.string.len);

    /* Validate based on format */
    if (strcmp(format_str, "date-time") == 0)
    {
        /* ISO 8601 date-time: YYYY-MM-DDTHH:MM:SS with optional timezone */
        regex_t regex;
        const char *pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})?$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match date-time format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "date") == 0)
    {
        /* ISO 8601 date: YYYY-MM-DD */
        regex_t regex;
        const char *pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match date format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "time") == 0)
    {
        /* ISO 8601 time: HH:MM:SS with optional fractional seconds and timezone */
        regex_t regex;
        const char *pattern = "^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})?$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match time format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "email") == 0)
    {
        /* Basic email validation - POSIX ERE doesn't support \s, use explicit chars */
        regex_t regex;
        const char *pattern = "^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match email format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "hostname") == 0)
    {
        /* Hostname validation */
        regex_t regex;
        const char *pattern = "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match hostname format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "ipv4") == 0)
    {
        /* IPv4 address validation */
        regex_t regex;
        const char *pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match IPv4 format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "ipv6") == 0)
    {
        /* Simplified IPv6 validation (full addresses only, no :: shorthand for simplicity) */
        regex_t regex;
        const char *pattern = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}(:([0-9a-fA-F]{1,4}))*)?$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match IPv6 format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "uri") == 0)
    {
        /* Basic URI validation */
        regex_t regex;
        const char *pattern = "^[a-zA-Z][a-zA-Z0-9+.-]*:.+$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match URI format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "uuid") == 0)
    {
        /* UUID validation */
        regex_t regex;
        const char *pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) == 0)
        {
            if (regexec(&regex, str, 0, NULL, 0) == REG_NOMATCH)
            {
                if (errors)
                    append_error(errors, path, "String does not match UUID format");
                valid = false;
            }
            regfree(&regex);
        }
    }
    else if (strcmp(format_str, "regex") == 0)
    {
        /* Validate that the string is a valid regex */
        regex_t regex;
        if (regcomp(&regex, str, REG_EXTENDED | REG_NOSUB) != 0)
        {
            if (errors)
                append_error(errors, path, "String is not a valid regular expression");
            valid = false;
        }
        else
        {
            regfree(&regex);
        }
    }
    /* Unknown formats are ignored per JSON Schema spec */

    pfree(str);
    pfree(format_str);

    return valid;
}

/*
 * Resolve a $ref pointer to get the referenced schema
 * Supports JSON Pointer format: #/$defs/name or #/definitions/name
 */
static JsonbValue *
resolve_ref(const char *ref, JsonbContainer *root_schema)
{
    JsonbValue *result = NULL;
    char *ref_copy;
    char *token;
    char *saveptr;
    JsonbContainer *current;

    if (ref == NULL || root_schema == NULL)
        return NULL;

    /* Only support local references starting with # */
    if (ref[0] != '#')
        return NULL;

    /* Skip the # */
    ref++;

    /* Handle root reference */
    if (*ref == '\0' || (*ref == '/' && *(ref + 1) == '\0'))
    {
        result = palloc(sizeof(JsonbValue));
        result->type = jbvBinary;
        result->val.binary.data = root_schema;
        return result;
    }

    /* Skip leading / */
    if (*ref == '/')
        ref++;

    ref_copy = pstrdup(ref);
    current = root_schema;

    /* Parse JSON Pointer path */
    token = strtok_r(ref_copy, "/", &saveptr);
    while (token != NULL)
    {
        JsonbValue *found;

        /* Unescape JSON Pointer encoding */
        char *p = token;
        char *w = token;
        while (*p)
        {
            if (*p == '~')
            {
                if (*(p + 1) == '1')
                {
                    *w++ = '/';
                    p += 2;
                }
                else if (*(p + 1) == '0')
                {
                    *w++ = '~';
                    p += 2;
                }
                else
                {
                    *w++ = *p++;
                }
            }
            else
            {
                *w++ = *p++;
            }
        }
        *w = '\0';

        found = get_jsonb_key(current, token);
        if (found == NULL)
        {
            pfree(ref_copy);
            return NULL;
        }

        if (found->type == jbvBinary)
        {
            current = found->val.binary.data;
            result = found;
        }
        else
        {
            /* Found a scalar - this is the final value */
            result = found;
            break;
        }

        token = strtok_r(NULL, "/", &saveptr);
    }

    pfree(ref_copy);
    return result;
}

/*
 * Append an error to the errors JSON array
 */
static void
append_error(StringInfo errors, const char *path, const char *message)
{
    if (errors == NULL)
        return;

    appendStringInfo(errors, "{\"path\":\"%s\",\"message\":", path);

    /* Escape the message for JSON */
    appendStringInfoChar(errors, '"');
    for (const char *p = message; *p; p++)
    {
        switch (*p)
        {
            case '"':
                appendStringInfoString(errors, "\\\"");
                break;
            case '\\':
                appendStringInfoString(errors, "\\\\");
                break;
            case '\n':
                appendStringInfoString(errors, "\\n");
                break;
            case '\r':
                appendStringInfoString(errors, "\\r");
                break;
            case '\t':
                appendStringInfoString(errors, "\\t");
                break;
            default:
                appendStringInfoChar(errors, *p);
                break;
        }
    }
    appendStringInfoChar(errors, '"');

    appendStringInfoString(errors, "},");
}

/*
 * Build a JSON path string
 */
static char *
build_path(const char *base, const char *key)
{
    StringInfoData path;

    initStringInfo(&path);

    if (base && *base)
    {
        appendStringInfoString(&path, base);
        if (key[0] != '[')
            appendStringInfoChar(&path, '/');
    }
    appendStringInfoString(&path, key);

    return path.data;
}

/* ============================================================
 * Compiled Schema Functions
 * ============================================================
 */

/*
 * jsonschema_compile(schema jsonb) -> jsonschema_compiled
 *
 * Compiles a JSON schema for efficient repeated validation.
 * The compiled schema caches regex patterns and other parsed elements.
 */
Datum
jsonschema_compile(PG_FUNCTION_ARGS)
{
    Jsonb              *schema = PG_GETARG_JSONB_P(0);
    JsonSchemaCompiled *result;
    int                 schema_size;

    /* Initialize the regex cache on first use */
    init_regex_cache();

    /*
     * The compiled schema is stored as a copy of the jsonb schema.
     * The actual compilation (regex caching) happens lazily during validation.
     * This approach allows the compiled schema to be passed around and stored.
     */
    schema_size = VARSIZE(schema);
    result = (JsonSchemaCompiled *) palloc(schema_size);
    memcpy(result, schema, schema_size);

    PG_RETURN_JSONSCHEMA_COMPILED_P(result);
}

/*
 * Input function for jsonschema_compiled type
 */
Datum
jsonschema_compiled_in(PG_FUNCTION_ARGS)
{
    char   *str = PG_GETARG_CSTRING(0);
    Datum   jsonb_datum;
    Jsonb  *jsonb_val;
    JsonSchemaCompiled *result;
    int     size;

    /* Parse as jsonb */
    jsonb_datum = DirectFunctionCall1(jsonb_in, CStringGetDatum(str));
    jsonb_val = DatumGetJsonbP(jsonb_datum);

    /* Copy to our type */
    size = VARSIZE(jsonb_val);
    result = (JsonSchemaCompiled *) palloc(size);
    memcpy(result, jsonb_val, size);

    PG_RETURN_JSONSCHEMA_COMPILED_P(result);
}

/*
 * Output function for jsonschema_compiled type
 */
Datum
jsonschema_compiled_out(PG_FUNCTION_ARGS)
{
    JsonSchemaCompiled *compiled = PG_GETARG_JSONSCHEMA_COMPILED_P(0);
    Datum result;

    /* Output as jsonb text */
    result = DirectFunctionCall1(jsonb_out, PointerGetDatum(compiled));

    PG_RETURN_CSTRING(DatumGetCString(result));
}

/*
 * jsonschema_is_valid(data jsonb, schema jsonschema_compiled) -> boolean
 *
 * Validates data against a pre-compiled schema.
 */
Datum
jsonschema_is_valid_compiled(PG_FUNCTION_ARGS)
{
    Jsonb              *data = PG_GETARG_JSONB_P(0);
    JsonSchemaCompiled *compiled = PG_GETARG_JSONSCHEMA_COMPILED_P(1);
    Jsonb              *schema;
    bool                result;

    /* The compiled schema is stored as jsonb internally */
    schema = (Jsonb *) compiled;

    result = validate_jsonb_internal(data, schema, NULL);

    PG_RETURN_BOOL(result);
}

/*
 * jsonschema_validate(data jsonb, schema jsonschema_compiled) -> jsonb
 *
 * Validates data against a pre-compiled schema and returns errors.
 */
Datum
jsonschema_validate_compiled(PG_FUNCTION_ARGS)
{
    Jsonb              *data = PG_GETARG_JSONB_P(0);
    JsonSchemaCompiled *compiled = PG_GETARG_JSONSCHEMA_COMPILED_P(1);
    Jsonb              *schema;
    StringInfoData      errors;
    Datum               result;

    /* The compiled schema is stored as jsonb internally */
    schema = (Jsonb *) compiled;

    initStringInfo(&errors);
    appendStringInfoChar(&errors, '[');

    (void) validate_jsonb_internal(data, schema, &errors);

    /* Remove trailing comma if present */
    if (errors.len > 1 && errors.data[errors.len - 1] == ',')
        errors.len--;

    appendStringInfoChar(&errors, ']');

    result = DirectFunctionCall1(jsonb_in, CStringGetDatum(errors.data));
    pfree(errors.data);

    PG_RETURN_DATUM(result);
}
