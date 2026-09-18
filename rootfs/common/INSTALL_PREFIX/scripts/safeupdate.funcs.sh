#!/bin/sh
# {# jinja-parse #}

# Subset of OSP error codes, see core/src/lib/osp/inc/osp_upg.h for more info
OSP_UPG_FL_WRITE=9

upg_image_write()
{
    {% if CONFIG_WPD_ENABLED %}
    # Before upgrade disable WPD if it exists.
    WPD=/etc/init.d/wpd
    [ -x ${WPD} ] && ${WPD} stop
    {% endif %}
    sysupgrade -n "$1" || exit $OSP_UPG_FL_WRITE
}

upg_image_commit()
{
    return 0
}
