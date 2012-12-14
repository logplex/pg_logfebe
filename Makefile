MODULE_big = pg_logfebe
OBJS = pg_logfebe.o

EXTENSION = pg_logfebe

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
