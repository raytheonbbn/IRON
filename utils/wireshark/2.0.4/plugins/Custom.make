#

_CUSTOM_SUBDIRS_ = \
	lrm \
	fec \
	mgen \
	sliq \
	qlam

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/lrm/lrm.la \
	-dlopen plugins/fec/fec.la \
	-dlopen plugins/mgen/mgen.la \
	-dlopen plugins/sliq/sliq.la \
	-dlopen plugins/qlam/qlam.la
