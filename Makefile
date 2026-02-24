EXTENSION = json_schema_validate
MODULE_big = json_schema_validate
OBJS = json_schema_validate.o

DATA = json_schema_validate--0.1.0.sql
REGRESS = json_schema_validate

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
