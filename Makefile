EXTENSION = json_schema_val
MODULE_big = json_schema_val
OBJS = json_schema_val.o

DATA = json_schema_val--0.1.0.sql
REGRESS = json_schema_val

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
