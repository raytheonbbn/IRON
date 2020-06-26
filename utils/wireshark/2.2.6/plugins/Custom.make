#

_CUSTOM_SUBDIRS_ = \
        fec \
        lrm \
        mgen \
        qlam \
        sliq \
        kupd \
        ironlsa \
        rrm


_CUSTOM_EXTRA_DIST_ = \
        Custom.m4 \
        Custom.make

_CUSTOM_plugin_ldadd_ = \
        -dlopen plugins/fec/fec.la \
        -dlopen plugins/lrm/lrm.la \
        -dlopen plugins/mgen/mgen.la \
        -dlopen plugins/qlam/qlam.la \
        -dlopen plugins/sliq/sliq.la \
        -dlopen plugins/kupd/kupd.la \
        -dlopen plugins/ironlsa/ironlsa.la \
        -dlopen plugins/rrm/rrm.la

