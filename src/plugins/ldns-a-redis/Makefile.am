
pkglib_LTLIBRARIES = \
	libdcplugin_ldns_a_redis.la

libdcplugin_ldns_a_redis_la_LIBTOOLFLAGS = --tag=disable-static

libdcplugin_ldns_a_redis_la_SOURCES = \
	ldns-a-redis.c

libdcplugin_ldns_a_redis_la_LIBADD = @LDNS_LIBS@ @REDIS_LIBS@

libdcplugin_ldns_a_redis_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-avoid-version \
	-export-dynamic \
	-module \
	-no-undefined

libdcplugin_ldns_a_redis_la_CPPFLAGS = \
	$(LTDLINCL) \
	@REDIS_CFLAGS@ \
	-I../../include
