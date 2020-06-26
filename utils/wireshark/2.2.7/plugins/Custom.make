#

_CUSTOM_SUBDIRS_ = \
        mgen \
        qlam \
        sliq \
        cat \
        cce \
        kupd \
        ironlsa \
        rrm


_CUSTOM_EXTRA_DIST_ = \
        Custom.m4 \
        Custom.make

_CUSTOM_plugin_ldadd_ = \
        -dlopen plugins/mgen/mgen.la \
        -dlopen plugins/qlam/qlam.la \
        -dlopen plugins/sliq/sliq.la \
        -dlopen plugins/cat/cat.la \
        -dlopen plugins/cce/cce.la \
        -dlopen plugins/kupd/kupd.la \
        -dlopen plugins/ironlsa/ironlsa.la \
        -dlopen plugins/rrm/rrm.la

