short_ver = 1.4
long_ver = $(shell (git describe --tags --long '--match=v*' 2>/dev/null || echo $(short_ver)-0-unknown) | cut -c2-)

MODULE_big = pg_logfebe
OBJS = pg_logfebe.o

EXTENSION = pg_logfebe

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

DEBUILD_ROOT = /tmp/pg_logfebe

deb:
	mkdir -p $(DEBUILD_ROOT) && rm -rf $(DEBUILD_ROOT)/*
	rsync -Ca --exclude=build/* ./ $(DEBUILD_ROOT)/
	cd $(DEBUILD_ROOT) && make -f debian/rules orig
	cd $(DEBUILD_ROOT) && debuild -us -uc -sa
	cp -a /tmp/pg_logfebe* /tmp/postgresql-9.* build/
