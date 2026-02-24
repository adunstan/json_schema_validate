# json_schema_val

A PostgreSQL extension for validating JSON/JSONB data against JSON Schema.

## Overview

`json_schema_val` provides functions to validate `json` and `jsonb` data against [JSON Schema](https://json-schema.org/) specifications directly within PostgreSQL. This enables schema-based data validation in CHECK constraints, triggers, queries, and stored procedures.

## Features

- Validates both `json` and `jsonb` types
- Returns boolean for simple validation or detailed error messages
- Supports most JSON Schema Draft 7 keywords
- Schema composition with `allOf`, `anyOf`, `oneOf`, `not`
- Schema reuse with `$ref` and `$defs`
- Immutable and parallel-safe functions

## Installation

### Requirements

- PostgreSQL 14 or later
- C compiler (gcc or clang)
- PostgreSQL development headers

### Build and Install

```bash
# Clone or download the source
cd json_schema_val

# Build (adjust PG_CONFIG path as needed)
make PG_CONFIG=/path/to/pg_config

# Install
sudo make install PG_CONFIG=/path/to/pg_config

# Or without sudo if you have write access to PostgreSQL directories
make install PG_CONFIG=/path/to/pg_config
```

### Enable in Database

```sql
CREATE EXTENSION json_schema_val;
```

## Functions

### jsonschema_is_valid

```sql
jsonschema_is_valid(data jsonb, schema jsonb) → boolean
jsonschema_is_valid(data json, schema json) → boolean
```

Returns `true` if the data validates against the schema, `false` otherwise.

### jsonschema_validate

```sql
jsonschema_validate(data jsonb, schema jsonb) → jsonb
jsonschema_validate(data json, schema json) → json
```

Returns `NULL` if valid, or a JSON array of error objects if invalid. Each error object contains:
- `path`: JSON path to the invalid value
- `message`: Description of the validation failure

### jsonschema_compile

```sql
jsonschema_compile(schema jsonb) → jsonschema_compiled
```

Compiles a JSON schema for efficient repeated validation. The compiled schema caches regex patterns and can be stored in tables or wrapped in functions for reuse.

### Compiled Schema Overloads

```sql
jsonschema_is_valid(data jsonb, schema jsonschema_compiled) → boolean
jsonschema_validate(data jsonb, schema jsonschema_compiled) → jsonb
```

Validate using a pre-compiled schema. See [Compiled Schemas](#compiled-schemas) for usage examples.

## Usage Examples

### Basic Type Validation

```sql
-- Validate type
SELECT jsonschema_is_valid('{"name": "John"}', '{"type": "object"}');
-- Returns: true

SELECT jsonschema_is_valid('"hello"', '{"type": "object"}');
-- Returns: false
```

### Required Properties

```sql
SELECT jsonschema_is_valid(
    '{"id": 1, "name": "John"}',
    '{"type": "object", "required": ["id", "name"]}'
);
-- Returns: true

SELECT jsonschema_is_valid(
    '{"id": 1}',
    '{"type": "object", "required": ["id", "name"]}'
);
-- Returns: false
```

### Property Validation

```sql
SELECT jsonschema_is_valid(
    '{"age": 25, "name": "John"}',
    '{
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer", "minimum": 0}
        }
    }'
);
-- Returns: true
```

### Reject Additional Properties

```sql
SELECT jsonschema_is_valid(
    '{"name": "John", "extra": "field"}',
    '{
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "additionalProperties": false
    }'
);
-- Returns: false
```

### Schema Composition

```sql
-- allOf: must match ALL schemas
SELECT jsonschema_is_valid(
    '{"name": "John", "age": 30}',
    '{
        "allOf": [
            {"required": ["name"]},
            {"required": ["age"]}
        ]
    }'
);
-- Returns: true

-- anyOf: must match AT LEAST ONE schema
SELECT jsonschema_is_valid(
    '"hello"',
    '{"anyOf": [{"type": "string"}, {"type": "number"}]}'
);
-- Returns: true

-- oneOf: must match EXACTLY ONE schema
SELECT jsonschema_is_valid(
    '5',
    '{"oneOf": [{"type": "string"}, {"type": "number"}]}'
);
-- Returns: true

-- not: must NOT match
SELECT jsonschema_is_valid(
    '"hello"',
    '{"not": {"type": "number"}}'
);
-- Returns: true
```

### Schema References ($ref)

```sql
SELECT jsonschema_is_valid(
    '{"user": {"name": "John", "email": "john@example.com"}}',
    '{
        "$defs": {
            "person": {
                "type": "object",
                "required": ["name", "email"],
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"}
                }
            }
        },
        "type": "object",
        "properties": {
            "user": {"$ref": "#/$defs/person"}
        }
    }'
);
-- Returns: true
```

### Getting Validation Errors

```sql
SELECT jsonschema_validate(
    '{"name": 123, "age": "thirty"}',
    '{
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "number"}
        }
    }'
);
-- Returns: [
--   {"path": "name", "message": "Expected type string but got number"},
--   {"path": "age", "message": "Expected type number but got string"}
-- ]
```

### CHECK Constraints

```sql
CREATE TABLE users (
    id serial PRIMARY KEY,
    data jsonb NOT NULL CHECK (
        jsonschema_is_valid(data, '{
            "type": "object",
            "required": ["name", "email"],
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "email": {"type": "string", "pattern": "^[^@]+@[^@]+$"},
                "age": {"type": "integer", "minimum": 0}
            },
            "additionalProperties": false
        }')
    )
);

-- This succeeds
INSERT INTO users (data) VALUES ('{"name": "John", "email": "john@example.com"}');

-- This fails with CHECK constraint violation
INSERT INTO users (data) VALUES ('{"name": "John"}');
-- ERROR: new row for relation "users" violates check constraint

-- This also fails (invalid email format)
INSERT INTO users (data) VALUES ('{"name": "John", "email": "invalid"}');
```

### Storing Schema in a Table

```sql
-- Create a table to store schemas
CREATE TABLE json_schemas (
    name text PRIMARY KEY,
    schema jsonb NOT NULL
);

-- Insert a schema
INSERT INTO json_schemas VALUES (
    'user',
    '{
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        }
    }'
);

-- Validate using stored schema
SELECT jsonschema_is_valid(
    '{"name": "John", "age": 30}',
    (SELECT schema FROM json_schemas WHERE name = 'user')
);
```

## Supported JSON Schema Keywords

### Type Keywords

| Keyword | Description |
|---------|-------------|
| `type` | Validates value type (object, array, string, number, integer, boolean, null) |
| `enum` | Value must be one of the specified values |
| `const` | Value must exactly match |

### String Keywords

| Keyword | Description |
|---------|-------------|
| `minLength` | Minimum string length |
| `maxLength` | Maximum string length |
| `pattern` | String must match regex pattern |

### Number Keywords

| Keyword | Description |
|---------|-------------|
| `minimum` | Value >= minimum |
| `maximum` | Value <= maximum |
| `exclusiveMinimum` | Value > exclusiveMinimum |
| `exclusiveMaximum` | Value < exclusiveMaximum |

### Array Keywords

| Keyword | Description |
|---------|-------------|
| `minItems` | Minimum array length |
| `maxItems` | Maximum array length |
| `items` | Schema for array items |

### Object Keywords

| Keyword | Description |
|---------|-------------|
| `required` | List of required property names |
| `properties` | Schema for each property |
| `additionalProperties` | Schema for unlisted properties, or `false` to reject |
| `propertyNames` | Schema that property names must match |

### Schema Composition

| Keyword | Description |
|---------|-------------|
| `allOf` | Must match ALL schemas in array |
| `anyOf` | Must match AT LEAST ONE schema in array |
| `oneOf` | Must match EXACTLY ONE schema in array |
| `not` | Must NOT match the schema |

### References

| Keyword | Description |
|---------|-------------|
| `$ref` | Reference to another schema (JSON Pointer format) |
| `$defs` | Schema definitions for reuse |
| `definitions` | Alias for `$defs` (older style) |

## Limitations

The following JSON Schema features are not yet implemented:

- `format` (semantic validation like email, uri, date)
- `multipleOf` (number divisibility)
- `uniqueItems` (array uniqueness)
- `contains`, `minContains`, `maxContains`
- `prefixItems` / tuple validation
- `dependentRequired`, `dependentSchemas`
- `if` / `then` / `else`
- `patternProperties` (partial support in additionalProperties logic)
- External `$ref` (only local `#/...` references supported)
- `$id`, `$anchor`

## Performance Considerations

- Functions are marked `IMMUTABLE` and `PARALLEL SAFE` for query optimization
- Regex patterns are automatically cached in memory for the backend session
- Complex schemas with many `allOf`/`anyOf`/`oneOf` may have higher overhead
- JSONB is generally faster than JSON due to pre-parsed binary format

### Compiled Schemas

For frequently-used schemas, use `jsonschema_compile()` to create a compiled schema handle:

```sql
-- Create a reusable compiled schema
CREATE FUNCTION get_user_schema() RETURNS jsonschema_compiled AS $$
    SELECT jsonschema_compile('{
        "type": "object",
        "required": ["name", "email"],
        "properties": {
            "name": {"type": "string"},
            "email": {"type": "string", "pattern": "^[^@]+@[^@]+$"}
        }
    }'::jsonb);
$$ LANGUAGE SQL IMMUTABLE;

-- Use the compiled schema (regex patterns are cached)
SELECT jsonschema_is_valid(data, get_user_schema()) FROM users;
```

Compiled schemas can also be stored in tables:

```sql
CREATE TABLE schemas (name text PRIMARY KEY, schema jsonschema_compiled);
INSERT INTO schemas VALUES ('user', jsonschema_compile('...'::jsonb));

-- Validate using stored schema
SELECT jsonschema_is_valid(data, s.schema)
FROM users u, schemas s
WHERE s.name = 'user';
```

## License

This extension is released under the PostgreSQL License.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## See Also

- [JSON Schema Specification](https://json-schema.org/)
- [Understanding JSON Schema](https://json-schema.org/understanding-json-schema/)
- [PostgreSQL JSON Functions](https://www.postgresql.org/docs/current/functions-json.html)
