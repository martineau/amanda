# SYNOPSIS
#
#   AMANDA_NDMP_DEVICE
#
# OVERVIEW
#
#   Set up for the 'ndmp' device.  WANT_NDMP_DEVICE is
#   defined and AM_CONDITIONAL'd if the ndmp device should be supported (if
#   at least one of the backends is available).
#
#
AC_DEFUN([AMANDA_NDMP_DEVICE], [

    AC_ARG_ENABLE([ndmp-device],
        AS_HELP_STRING([--disable-ndmp-device],
                       [disable the ndmp device]),
        [ WANT_NDMP_DEVICE=$enableval ], [ WANT_NDMP_DEVICE=$WANT_NDMP ])

    if test x"$WANT_NDMP" != x"yes" -a x"WANT_NDMP_DEVICE" = x"yes"; then
	WANT_NDMP_DEVICE=no
	AC_MSG_RESULT($WANT_NDMP_DEVICE)
	AC_MSG_ERROR([Cannot build the ndmp device: ndmp is not build.])
    else
	AC_MSG_RESULT($WANT_NDMP_DEVICE)
    fi

    AC_DEFINE(WANT_NDMP_DEVICE, 1, [Define if the ndmp-device will be built])
    AM_CONDITIONAL([WANT_NDMP_DEVICE], [test x"$WANT_NDMP_DEVICE" = x"yes"])
])
