-- JSON Schema validation extension for PostgreSQL

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
