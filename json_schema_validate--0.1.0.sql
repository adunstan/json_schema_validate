-- JSON Schema validation extension for PostgreSQL
\echo Use "CREATE EXTENSION json_schema_validate" to load this file. \quit

-- Validate jsonb data against a JSON Schema
-- Returns true if valid, false otherwise
CREATE FUNCTION jsonschema_is_valid(data jsonb, schema jsonb)
RETURNS boolean
AS 'MODULE_PATHNAME', 'jsonschema_is_valid_jsonb'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Validate json data against a JSON Schema
-- Returns true if valid, false otherwise
CREATE FUNCTION jsonschema_is_valid(data json, schema json)
RETURNS boolean
AS 'MODULE_PATHNAME', 'jsonschema_is_valid_json'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Validate jsonb data and return detailed errors
-- Returns NULL if valid, or a JSONB array of error objects if invalid
CREATE FUNCTION jsonschema_validate(data jsonb, schema jsonb)
RETURNS jsonb
AS 'MODULE_PATHNAME', 'jsonschema_validate_jsonb'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Validate json data and return detailed errors
-- Returns NULL if valid, or a JSON array of error objects if invalid
CREATE FUNCTION jsonschema_validate(data json, schema json)
RETURNS json
AS 'MODULE_PATHNAME', 'jsonschema_validate_json'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- ============================================================
-- Compiled Schema Support
-- ============================================================

-- Create the compiled schema type
-- Input function
CREATE FUNCTION jsonschema_compiled_in(cstring)
RETURNS jsonschema_compiled
AS 'MODULE_PATHNAME', 'jsonschema_compiled_in'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Output function
CREATE FUNCTION jsonschema_compiled_out(jsonschema_compiled)
RETURNS cstring
AS 'MODULE_PATHNAME', 'jsonschema_compiled_out'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Create the type
CREATE TYPE jsonschema_compiled (
    INPUT = jsonschema_compiled_in,
    OUTPUT = jsonschema_compiled_out,
    LIKE = jsonb
);

-- Compile a JSON schema for efficient repeated validation
-- Caches regex patterns and other parsed elements
CREATE FUNCTION jsonschema_compile(schema jsonb)
RETURNS jsonschema_compiled
AS 'MODULE_PATHNAME', 'jsonschema_compile'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Validate jsonb data against a compiled schema
-- Returns true if valid, false otherwise
CREATE FUNCTION jsonschema_is_valid(data jsonb, schema jsonschema_compiled)
RETURNS boolean
AS 'MODULE_PATHNAME', 'jsonschema_is_valid_compiled'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;

-- Validate jsonb data against a compiled schema and return errors
-- Returns NULL if valid, or a JSONB array of error objects if invalid
CREATE FUNCTION jsonschema_validate(data jsonb, schema jsonschema_compiled)
RETURNS jsonb
AS 'MODULE_PATHNAME', 'jsonschema_validate_compiled'
LANGUAGE C IMMUTABLE PARALLEL SAFE STRICT;
