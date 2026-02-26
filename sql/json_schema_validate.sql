-- json_schema_validate extension tests

CREATE EXTENSION json_schema_validate;

--
-- Type validation
--
SELECT 'type: object' AS test, jsonschema_is_valid('{}'::jsonb, '{"type": "object"}'::jsonb) AS result;
SELECT 'type: array' AS test, jsonschema_is_valid('[]'::jsonb, '{"type": "array"}'::jsonb) AS result;
SELECT 'type: string' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"type": "string"}'::jsonb) AS result;
SELECT 'type: number' AS test, jsonschema_is_valid('42'::jsonb, '{"type": "number"}'::jsonb) AS result;
SELECT 'type: integer' AS test, jsonschema_is_valid('42'::jsonb, '{"type": "integer"}'::jsonb) AS result;
SELECT 'type: boolean' AS test, jsonschema_is_valid('true'::jsonb, '{"type": "boolean"}'::jsonb) AS result;
SELECT 'type: null' AS test, jsonschema_is_valid('null'::jsonb, '{"type": "null"}'::jsonb) AS result;

-- Type mismatches
SELECT 'type mismatch: string vs object' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"type": "object"}'::jsonb) AS result;
SELECT 'type mismatch: number vs string' AS test, jsonschema_is_valid('42'::jsonb, '{"type": "string"}'::jsonb) AS result;

--
-- Enum validation
--
SELECT 'enum: valid' AS test, jsonschema_is_valid('"a"'::jsonb, '{"enum": ["a", "b", "c"]}'::jsonb) AS result;
SELECT 'enum: invalid' AS test, jsonschema_is_valid('"d"'::jsonb, '{"enum": ["a", "b", "c"]}'::jsonb) AS result;
SELECT 'enum: number' AS test, jsonschema_is_valid('2'::jsonb, '{"enum": [1, 2, 3]}'::jsonb) AS result;

--
-- Const validation
--
SELECT 'const: match string' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"const": "hello"}'::jsonb) AS result;
SELECT 'const: no match' AS test, jsonschema_is_valid('"world"'::jsonb, '{"const": "hello"}'::jsonb) AS result;
SELECT 'const: match number' AS test, jsonschema_is_valid('42'::jsonb, '{"const": 42}'::jsonb) AS result;
SELECT 'const: match boolean' AS test, jsonschema_is_valid('true'::jsonb, '{"const": true}'::jsonb) AS result;
SELECT 'const: match null' AS test, jsonschema_is_valid('null'::jsonb, '{"const": null}'::jsonb) AS result;

--
-- String constraints
--
SELECT 'minLength: valid' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"minLength": 3}'::jsonb) AS result;
SELECT 'minLength: invalid' AS test, jsonschema_is_valid('"hi"'::jsonb, '{"minLength": 3}'::jsonb) AS result;
SELECT 'maxLength: valid' AS test, jsonschema_is_valid('"hi"'::jsonb, '{"maxLength": 5}'::jsonb) AS result;
SELECT 'maxLength: invalid' AS test, jsonschema_is_valid('"hello world"'::jsonb, '{"maxLength": 5}'::jsonb) AS result;
SELECT 'pattern: valid' AS test, jsonschema_is_valid('"abc123"'::jsonb, '{"pattern": "^[a-z]+[0-9]+$"}'::jsonb) AS result;
SELECT 'pattern: invalid' AS test, jsonschema_is_valid('"123abc"'::jsonb, '{"pattern": "^[a-z]+[0-9]+$"}'::jsonb) AS result;

--
-- Number constraints
--
SELECT 'minimum: valid' AS test, jsonschema_is_valid('10'::jsonb, '{"minimum": 5}'::jsonb) AS result;
SELECT 'minimum: invalid' AS test, jsonschema_is_valid('3'::jsonb, '{"minimum": 5}'::jsonb) AS result;
SELECT 'minimum: equal' AS test, jsonschema_is_valid('5'::jsonb, '{"minimum": 5}'::jsonb) AS result;
SELECT 'maximum: valid' AS test, jsonschema_is_valid('3'::jsonb, '{"maximum": 5}'::jsonb) AS result;
SELECT 'maximum: invalid' AS test, jsonschema_is_valid('10'::jsonb, '{"maximum": 5}'::jsonb) AS result;
SELECT 'exclusiveMinimum: valid' AS test, jsonschema_is_valid('6'::jsonb, '{"exclusiveMinimum": 5}'::jsonb) AS result;
SELECT 'exclusiveMinimum: invalid' AS test, jsonschema_is_valid('5'::jsonb, '{"exclusiveMinimum": 5}'::jsonb) AS result;
SELECT 'exclusiveMaximum: valid' AS test, jsonschema_is_valid('4'::jsonb, '{"exclusiveMaximum": 5}'::jsonb) AS result;
SELECT 'exclusiveMaximum: invalid' AS test, jsonschema_is_valid('5'::jsonb, '{"exclusiveMaximum": 5}'::jsonb) AS result;

--
-- Array constraints
--
SELECT 'minItems: valid' AS test, jsonschema_is_valid('[1, 2, 3]'::jsonb, '{"minItems": 2}'::jsonb) AS result;
SELECT 'minItems: invalid' AS test, jsonschema_is_valid('[1]'::jsonb, '{"minItems": 2}'::jsonb) AS result;
SELECT 'maxItems: valid' AS test, jsonschema_is_valid('[1, 2]'::jsonb, '{"maxItems": 3}'::jsonb) AS result;
SELECT 'maxItems: invalid' AS test, jsonschema_is_valid('[1, 2, 3, 4]'::jsonb, '{"maxItems": 3}'::jsonb) AS result;
SELECT 'items: valid' AS test, jsonschema_is_valid('[1, 2, 3]'::jsonb, '{"items": {"type": "number"}}'::jsonb) AS result;
SELECT 'items: invalid' AS test, jsonschema_is_valid('[1, "two", 3]'::jsonb, '{"items": {"type": "number"}}'::jsonb) AS result;

--
-- Object constraints: required
--
SELECT 'required: valid' AS test, jsonschema_is_valid('{"a": 1, "b": 2}'::jsonb, '{"required": ["a", "b"]}'::jsonb) AS result;
SELECT 'required: missing one' AS test, jsonschema_is_valid('{"a": 1}'::jsonb, '{"required": ["a", "b"]}'::jsonb) AS result;
SELECT 'required: missing all' AS test, jsonschema_is_valid('{}'::jsonb, '{"required": ["a", "b"]}'::jsonb) AS result;

--
-- Object constraints: properties
--
SELECT 'properties: valid' AS test, jsonschema_is_valid(
    '{"name": "John", "age": 30}'::jsonb,
    '{"properties": {"name": {"type": "string"}, "age": {"type": "number"}}}'::jsonb
) AS result;
SELECT 'properties: invalid type' AS test, jsonschema_is_valid(
    '{"name": "John", "age": "thirty"}'::jsonb,
    '{"properties": {"name": {"type": "string"}, "age": {"type": "number"}}}'::jsonb
) AS result;

--
-- Object constraints: additionalProperties
--
SELECT 'additionalProperties false: valid' AS test, jsonschema_is_valid(
    '{"name": "John"}'::jsonb,
    '{"properties": {"name": {"type": "string"}}, "additionalProperties": false}'::jsonb
) AS result;
SELECT 'additionalProperties false: invalid' AS test, jsonschema_is_valid(
    '{"name": "John", "extra": 1}'::jsonb,
    '{"properties": {"name": {"type": "string"}}, "additionalProperties": false}'::jsonb
) AS result;
SELECT 'additionalProperties schema: valid' AS test, jsonschema_is_valid(
    '{"name": "John", "extra": 123}'::jsonb,
    '{"properties": {"name": {"type": "string"}}, "additionalProperties": {"type": "number"}}'::jsonb
) AS result;
SELECT 'additionalProperties schema: invalid' AS test, jsonschema_is_valid(
    '{"name": "John", "extra": "not a number"}'::jsonb,
    '{"properties": {"name": {"type": "string"}}, "additionalProperties": {"type": "number"}}'::jsonb
) AS result;

--
-- Object constraints: propertyNames
--
SELECT 'propertyNames: valid' AS test, jsonschema_is_valid(
    '{"foo": 1, "bar": 2}'::jsonb,
    '{"propertyNames": {"pattern": "^[a-z]+$"}}'::jsonb
) AS result;
SELECT 'propertyNames: invalid' AS test, jsonschema_is_valid(
    '{"Foo": 1, "bar": 2}'::jsonb,
    '{"propertyNames": {"pattern": "^[a-z]+$"}}'::jsonb
) AS result;
SELECT 'propertyNames minLength: valid' AS test, jsonschema_is_valid(
    '{"abc": 1}'::jsonb,
    '{"propertyNames": {"minLength": 2}}'::jsonb
) AS result;
SELECT 'propertyNames minLength: invalid' AS test, jsonschema_is_valid(
    '{"a": 1}'::jsonb,
    '{"propertyNames": {"minLength": 2}}'::jsonb
) AS result;

--
-- Schema composition: allOf
--
SELECT 'allOf: valid' AS test, jsonschema_is_valid(
    '{"a": 1, "b": 2}'::jsonb,
    '{"allOf": [{"required": ["a"]}, {"required": ["b"]}]}'::jsonb
) AS result;
SELECT 'allOf: invalid' AS test, jsonschema_is_valid(
    '{"a": 1}'::jsonb,
    '{"allOf": [{"required": ["a"]}, {"required": ["b"]}]}'::jsonb
) AS result;

--
-- Schema composition: anyOf
--
SELECT 'anyOf: match first' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"anyOf": [{"type": "string"}, {"type": "number"}]}'::jsonb) AS result;
SELECT 'anyOf: match second' AS test, jsonschema_is_valid('42'::jsonb, '{"anyOf": [{"type": "string"}, {"type": "number"}]}'::jsonb) AS result;
SELECT 'anyOf: no match' AS test, jsonschema_is_valid('true'::jsonb, '{"anyOf": [{"type": "string"}, {"type": "number"}]}'::jsonb) AS result;

--
-- Schema composition: oneOf
--
SELECT 'oneOf: exactly one' AS test, jsonschema_is_valid(
    '5'::jsonb,
    '{"oneOf": [{"type": "number", "minimum": 0}, {"type": "number", "maximum": 3}]}'::jsonb
) AS result;
SELECT 'oneOf: matches both' AS test, jsonschema_is_valid(
    '2'::jsonb,
    '{"oneOf": [{"type": "number", "minimum": 0}, {"type": "number", "maximum": 3}]}'::jsonb
) AS result;
SELECT 'oneOf: matches none' AS test, jsonschema_is_valid(
    '"hello"'::jsonb,
    '{"oneOf": [{"type": "number"}, {"type": "boolean"}]}'::jsonb
) AS result;

--
-- Schema composition: not
--
SELECT 'not: valid' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"not": {"type": "number"}}'::jsonb) AS result;
SELECT 'not: invalid' AS test, jsonschema_is_valid('42'::jsonb, '{"not": {"type": "number"}}'::jsonb) AS result;

--
-- $ref and $defs
--
SELECT '$ref with $defs: valid' AS test, jsonschema_is_valid(
    '{"name": "John"}'::jsonb,
    '{"$defs": {"nameType": {"type": "string"}}, "properties": {"name": {"$ref": "#/$defs/nameType"}}}'::jsonb
) AS result;
SELECT '$ref with $defs: invalid' AS test, jsonschema_is_valid(
    '{"name": 123}'::jsonb,
    '{"$defs": {"nameType": {"type": "string"}}, "properties": {"name": {"$ref": "#/$defs/nameType"}}}'::jsonb
) AS result;
SELECT '$ref with definitions: valid' AS test, jsonschema_is_valid(
    '{"user": {"name": "John"}}'::jsonb,
    '{"definitions": {"person": {"type": "object", "required": ["name"]}}, "properties": {"user": {"$ref": "#/definitions/person"}}}'::jsonb
) AS result;

--
-- Nested validation
--
SELECT 'nested objects: valid' AS test, jsonschema_is_valid(
    '{"user": {"profile": {"name": "John", "age": 30}}}'::jsonb,
    '{
        "properties": {
            "user": {
                "properties": {
                    "profile": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"},
                            "age": {"type": "number"}
                        }
                    }
                }
            }
        }
    }'::jsonb
) AS result;

SELECT 'nested arrays: valid' AS test, jsonschema_is_valid(
    '{"items": [{"id": 1}, {"id": 2}]}'::jsonb,
    '{
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "number"}}
                }
            }
        }
    }'::jsonb
) AS result;

--
-- Error reporting
--
SELECT 'errors: type mismatch' AS test, jsonschema_validate('{"age": "thirty"}'::jsonb, '{"properties": {"age": {"type": "number"}}}'::jsonb);
SELECT 'errors: missing required' AS test, jsonschema_validate('{}'::jsonb, '{"required": ["id"]}'::jsonb);
SELECT 'errors: additional property' AS test, jsonschema_validate('{"a": 1, "b": 2}'::jsonb, '{"properties": {"a": {}}, "additionalProperties": false}'::jsonb);
SELECT 'errors: multiple' AS test, jsonschema_validate(
    '{"name": 123, "age": "old"}'::jsonb,
    '{"properties": {"name": {"type": "string"}, "age": {"type": "number"}}}'::jsonb
);

--
-- json type (not just jsonb)
--
SELECT 'json type: is_valid' AS test, jsonschema_is_valid('{"a": 1}'::json, '{"type": "object"}'::json) AS result;
SELECT 'json type: validate' AS test, jsonschema_validate('{}'::json, '{"required": ["x"]}'::json);

--
-- Boolean schemas
--
SELECT 'boolean schema true' AS test, jsonschema_is_valid('{"anything": "goes"}'::jsonb, 'true'::jsonb) AS result;
SELECT 'boolean schema false' AS test, jsonschema_is_valid('{"anything": "goes"}'::jsonb, 'false'::jsonb) AS result;

--
-- Complex real-world example
--
SELECT 'complex: user registration' AS test, jsonschema_is_valid(
    '{
        "username": "johndoe",
        "email": "john@example.com",
        "password": "secret123",
        "profile": {
            "firstName": "John",
            "lastName": "Doe",
            "age": 30
        },
        "tags": ["developer", "postgresql"]
    }'::jsonb,
    '{
        "type": "object",
        "required": ["username", "email", "password"],
        "properties": {
            "username": {"type": "string", "minLength": 3, "maxLength": 20},
            "email": {"type": "string", "pattern": "^[^@]+@[^@]+\\.[^@]+$"},
            "password": {"type": "string", "minLength": 8},
            "profile": {
                "type": "object",
                "properties": {
                    "firstName": {"type": "string"},
                    "lastName": {"type": "string"},
                    "age": {"type": "integer", "minimum": 0}
                }
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "maxItems": 10
            }
        },
        "additionalProperties": false
    }'::jsonb
) AS result;

--
-- Compiled schema support
--
SELECT 'compile schema' AS test, jsonschema_compile('{"type": "object"}'::jsonb) IS NOT NULL AS result;

-- Compiled schema validation
WITH schema AS (
    SELECT jsonschema_compile('{"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "pattern": "^[A-Z]"}}}'::jsonb) AS compiled
)
SELECT 'compiled is_valid: true' AS test, jsonschema_is_valid('{"name": "John"}'::jsonb, compiled) AS result FROM schema;

WITH schema AS (
    SELECT jsonschema_compile('{"type": "object", "required": ["name"]}'::jsonb) AS compiled
)
SELECT 'compiled is_valid: false' AS test, jsonschema_is_valid('{}'::jsonb, compiled) AS result FROM schema;

WITH schema AS (
    SELECT jsonschema_compile('{"type": "object", "required": ["id"]}'::jsonb) AS compiled
)
SELECT 'compiled validate' AS test, jsonschema_validate('{}'::jsonb, compiled) FROM schema;

-- Compiled schema can be stored in tables
CREATE TABLE test_schemas (name text PRIMARY KEY, schema jsonschema_compiled);
INSERT INTO test_schemas VALUES ('user', jsonschema_compile('{"type": "object", "required": ["name"]}'::jsonb));
SELECT 'stored compiled schema' AS test, jsonschema_is_valid('{"name": "test"}'::jsonb, schema) AS result FROM test_schemas WHERE name = 'user';
DROP TABLE test_schemas;

-- Compiled schema with SQL function wrapper for reuse
CREATE FUNCTION get_user_schema() RETURNS jsonschema_compiled AS $$
    SELECT jsonschema_compile('{"type": "object", "required": ["name", "email"]}'::jsonb);
$$ LANGUAGE SQL IMMUTABLE;

SELECT 'function wrapped schema: valid' AS test, jsonschema_is_valid('{"name": "John", "email": "john@test.com"}'::jsonb, get_user_schema()) AS result;
SELECT 'function wrapped schema: invalid' AS test, jsonschema_is_valid('{"name": "John"}'::jsonb, get_user_schema()) AS result;

DROP FUNCTION get_user_schema();

--
-- multipleOf
--
SELECT 'multipleOf: valid (10 is multiple of 5)' AS test, jsonschema_is_valid('10'::jsonb, '{"multipleOf": 5}'::jsonb) AS result;
SELECT 'multipleOf: invalid (7 is not multiple of 3)' AS test, jsonschema_is_valid('7'::jsonb, '{"multipleOf": 3}'::jsonb) AS result;
SELECT 'multipleOf: valid decimal (4.5 is multiple of 1.5)' AS test, jsonschema_is_valid('4.5'::jsonb, '{"multipleOf": 1.5}'::jsonb) AS result;
SELECT 'multipleOf: zero is multiple of anything' AS test, jsonschema_is_valid('0'::jsonb, '{"multipleOf": 7}'::jsonb) AS result;

--
-- uniqueItems
--
SELECT 'uniqueItems: valid (all unique)' AS test, jsonschema_is_valid('[1, 2, 3]'::jsonb, '{"uniqueItems": true}'::jsonb) AS result;
SELECT 'uniqueItems: invalid (has duplicates)' AS test, jsonschema_is_valid('[1, 2, 2, 3]'::jsonb, '{"uniqueItems": true}'::jsonb) AS result;
SELECT 'uniqueItems: valid strings' AS test, jsonschema_is_valid('["a", "b", "c"]'::jsonb, '{"uniqueItems": true}'::jsonb) AS result;
SELECT 'uniqueItems: invalid duplicate strings' AS test, jsonschema_is_valid('["a", "b", "a"]'::jsonb, '{"uniqueItems": true}'::jsonb) AS result;
SELECT 'uniqueItems: false allows duplicates' AS test, jsonschema_is_valid('[1, 1, 1]'::jsonb, '{"uniqueItems": false}'::jsonb) AS result;

--
-- contains
--
SELECT 'contains: valid (has number)' AS test, jsonschema_is_valid('[1, "a", true]'::jsonb, '{"contains": {"type": "number"}}'::jsonb) AS result;
SELECT 'contains: invalid (no number)' AS test, jsonschema_is_valid('["a", "b", true]'::jsonb, '{"contains": {"type": "number"}}'::jsonb) AS result;
SELECT 'contains: valid (multiple matches)' AS test, jsonschema_is_valid('[1, 2, 3]'::jsonb, '{"contains": {"type": "number"}}'::jsonb) AS result;

--
-- minContains and maxContains
--
SELECT 'minContains: valid (has 2 numbers, min 2)' AS test, jsonschema_is_valid('[1, 2, "a"]'::jsonb, '{"contains": {"type": "number"}, "minContains": 2}'::jsonb) AS result;
SELECT 'minContains: invalid (has 1 number, min 2)' AS test, jsonschema_is_valid('[1, "a", "b"]'::jsonb, '{"contains": {"type": "number"}, "minContains": 2}'::jsonb) AS result;
SELECT 'maxContains: valid (has 2 numbers, max 3)' AS test, jsonschema_is_valid('[1, 2, "a"]'::jsonb, '{"contains": {"type": "number"}, "maxContains": 3}'::jsonb) AS result;
SELECT 'maxContains: invalid (has 4 numbers, max 2)' AS test, jsonschema_is_valid('[1, 2, 3, 4]'::jsonb, '{"contains": {"type": "number"}, "maxContains": 2}'::jsonb) AS result;
SELECT 'minContains 0: valid even with no matches' AS test, jsonschema_is_valid('["a", "b"]'::jsonb, '{"contains": {"type": "number"}, "minContains": 0}'::jsonb) AS result;

--
-- minProperties and maxProperties
--
SELECT 'minProperties: valid' AS test, jsonschema_is_valid('{"a": 1, "b": 2}'::jsonb, '{"minProperties": 2}'::jsonb) AS result;
SELECT 'minProperties: invalid' AS test, jsonschema_is_valid('{"a": 1}'::jsonb, '{"minProperties": 2}'::jsonb) AS result;
SELECT 'maxProperties: valid' AS test, jsonschema_is_valid('{"a": 1, "b": 2}'::jsonb, '{"maxProperties": 3}'::jsonb) AS result;
SELECT 'maxProperties: invalid' AS test, jsonschema_is_valid('{"a": 1, "b": 2, "c": 3, "d": 4}'::jsonb, '{"maxProperties": 3}'::jsonb) AS result;
SELECT 'minProperties + maxProperties: valid' AS test, jsonschema_is_valid('{"a": 1, "b": 2}'::jsonb, '{"minProperties": 1, "maxProperties": 3}'::jsonb) AS result;

--
-- if/then/else
--
SELECT 'if/then: valid (if matches, then validates)' AS test, jsonschema_is_valid(
    '{"type": "string", "value": "hello"}'::jsonb,
    '{"if": {"properties": {"type": {"const": "string"}}}, "then": {"properties": {"value": {"type": "string"}}}}'::jsonb
) AS result;
SELECT 'if/then: valid (if not matches, then skipped)' AS test, jsonschema_is_valid(
    '{"type": "number", "value": 42}'::jsonb,
    '{"if": {"properties": {"type": {"const": "string"}}}, "then": {"properties": {"value": {"type": "string"}}}}'::jsonb
) AS result;
SELECT 'if/then: invalid (if matches, then fails)' AS test, jsonschema_is_valid(
    '{"type": "string", "value": 123}'::jsonb,
    '{"if": {"properties": {"type": {"const": "string"}}}, "then": {"properties": {"value": {"type": "string"}}}}'::jsonb
) AS result;
SELECT 'if/else: valid (if not matches, else validates)' AS test, jsonschema_is_valid(
    '{"type": "number", "value": 42}'::jsonb,
    '{"if": {"properties": {"type": {"const": "string"}}}, "else": {"properties": {"value": {"type": "number"}}}}'::jsonb
) AS result;
SELECT 'if/else: invalid (if not matches, else fails)' AS test, jsonschema_is_valid(
    '{"type": "number", "value": "hello"}'::jsonb,
    '{"if": {"properties": {"type": {"const": "string"}}}, "else": {"properties": {"value": {"type": "number"}}}}'::jsonb
) AS result;
SELECT 'if/then/else: then branch' AS test, jsonschema_is_valid(
    '10'::jsonb,
    '{"if": {"minimum": 5}, "then": {"maximum": 20}, "else": {"minimum": -10}}'::jsonb
) AS result;
SELECT 'if/then/else: else branch' AS test, jsonschema_is_valid(
    '2'::jsonb,
    '{"if": {"minimum": 5}, "then": {"maximum": 20}, "else": {"minimum": -10}}'::jsonb
) AS result;

--
-- Type arrays
--
SELECT 'type array: string or null (string)' AS test, jsonschema_is_valid('"hello"'::jsonb, '{"type": ["string", "null"]}'::jsonb) AS result;
SELECT 'type array: string or null (null)' AS test, jsonschema_is_valid('null'::jsonb, '{"type": ["string", "null"]}'::jsonb) AS result;
SELECT 'type array: string or null (number fails)' AS test, jsonschema_is_valid('42'::jsonb, '{"type": ["string", "null"]}'::jsonb) AS result;
SELECT 'type array: multiple types' AS test, jsonschema_is_valid('true'::jsonb, '{"type": ["string", "number", "boolean"]}'::jsonb) AS result;
SELECT 'type array: integer or string' AS test, jsonschema_is_valid('42'::jsonb, '{"type": ["integer", "string"]}'::jsonb) AS result;

--
-- Integer type (strict check)
--
SELECT 'integer: valid whole number' AS test, jsonschema_is_valid('42'::jsonb, '{"type": "integer"}'::jsonb) AS result;
SELECT 'integer: invalid decimal' AS test, jsonschema_is_valid('42.5'::jsonb, '{"type": "integer"}'::jsonb) AS result;
SELECT 'integer: valid negative' AS test, jsonschema_is_valid('-10'::jsonb, '{"type": "integer"}'::jsonb) AS result;
SELECT 'integer: valid zero' AS test, jsonschema_is_valid('0'::jsonb, '{"type": "integer"}'::jsonb) AS result;

--
-- Format validation
--
SELECT 'format date-time: valid' AS test, jsonschema_is_valid('"2023-12-25T10:30:00Z"'::jsonb, '{"format": "date-time"}'::jsonb) AS result;
SELECT 'format date-time: valid with offset' AS test, jsonschema_is_valid('"2023-12-25T10:30:00+05:30"'::jsonb, '{"format": "date-time"}'::jsonb) AS result;
SELECT 'format date-time: invalid' AS test, jsonschema_is_valid('"not a date"'::jsonb, '{"format": "date-time"}'::jsonb) AS result;
SELECT 'format date: valid' AS test, jsonschema_is_valid('"2023-12-25"'::jsonb, '{"format": "date"}'::jsonb) AS result;
SELECT 'format date: invalid' AS test, jsonschema_is_valid('"25-12-2023"'::jsonb, '{"format": "date"}'::jsonb) AS result;
SELECT 'format time: valid' AS test, jsonschema_is_valid('"10:30:00"'::jsonb, '{"format": "time"}'::jsonb) AS result;
SELECT 'format time: valid with zone' AS test, jsonschema_is_valid('"10:30:00Z"'::jsonb, '{"format": "time"}'::jsonb) AS result;
SELECT 'format time: invalid' AS test, jsonschema_is_valid('"25:00:00"'::jsonb, '{"format": "time"}'::jsonb) AS result;
SELECT 'format email: valid' AS test, jsonschema_is_valid('"user@example.com"'::jsonb, '{"format": "email"}'::jsonb) AS result;
SELECT 'format email: invalid' AS test, jsonschema_is_valid('"not an email"'::jsonb, '{"format": "email"}'::jsonb) AS result;
SELECT 'format hostname: valid' AS test, jsonschema_is_valid('"example.com"'::jsonb, '{"format": "hostname"}'::jsonb) AS result;
SELECT 'format hostname: invalid' AS test, jsonschema_is_valid('"-invalid.com"'::jsonb, '{"format": "hostname"}'::jsonb) AS result;
SELECT 'format ipv4: valid' AS test, jsonschema_is_valid('"192.168.1.1"'::jsonb, '{"format": "ipv4"}'::jsonb) AS result;
SELECT 'format ipv4: invalid' AS test, jsonschema_is_valid('"256.1.1.1"'::jsonb, '{"format": "ipv4"}'::jsonb) AS result;
SELECT 'format ipv6: valid' AS test, jsonschema_is_valid('"2001:0db8:85a3:0000:0000:8a2e:0370:7334"'::jsonb, '{"format": "ipv6"}'::jsonb) AS result;
SELECT 'format ipv6: valid shorthand' AS test, jsonschema_is_valid('"::1"'::jsonb, '{"format": "ipv6"}'::jsonb) AS result;
SELECT 'format uri: valid' AS test, jsonschema_is_valid('"https://example.com/path"'::jsonb, '{"format": "uri"}'::jsonb) AS result;
SELECT 'format uri: invalid' AS test, jsonschema_is_valid('"not a uri"'::jsonb, '{"format": "uri"}'::jsonb) AS result;
SELECT 'format uuid: valid' AS test, jsonschema_is_valid('"550e8400-e29b-41d4-a716-446655440000"'::jsonb, '{"format": "uuid"}'::jsonb) AS result;
SELECT 'format uuid: invalid' AS test, jsonschema_is_valid('"not-a-uuid"'::jsonb, '{"format": "uuid"}'::jsonb) AS result;
SELECT 'format regex: valid' AS test, jsonschema_is_valid('"^[a-z]+$"'::jsonb, '{"format": "regex"}'::jsonb) AS result;
SELECT 'format regex: invalid' AS test, jsonschema_is_valid('"[invalid"'::jsonb, '{"format": "regex"}'::jsonb) AS result;
SELECT 'format unknown: ignored' AS test, jsonschema_is_valid('"anything"'::jsonb, '{"format": "unknown-format"}'::jsonb) AS result;

DROP EXTENSION json_schema_validate;
