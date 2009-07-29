#
# Copyright (c) 1998,1999,2000
#	Traakan, Inc., Los Altos, CA
#	All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice unmodified, this list of conditions, and the following
#    disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#
# Project:  NDMJOB
# Ident:    $Id: $
#
# Description
#
#	This illustrates the strata (layers) of the
#	NDMJOB/NDMJOBLIB software, the scope of key
#	header (.h) files, and the source files
#	constituting each layer.
#
#  -  -  -  -  -	+---------------------------------------+
#  ^  ^  ^  ^  ndmjob.h	| NDMJOB Command	ndmjob_*.c	|
#  |  |  |  |  -	+---------------------------------------+
#  |  |  |  |		          NDMJOBLIB API "job"
#  |  |  |  |		+---------------------------------------+  \
#  |  |  |  |		| Rules       (NDMJLR)  ndmjr_*.[ch]	|   \
#  |  |  |  ndmagents.h	| Agents      (NDMJLA)  ndma_*.c	|    |
#  |  |  |  -		+---------------------------------------+    |
#  |  |  ndmlib.h	| Library     (NDMJLL)  ndml_*.c	|    |
#  |  |  -		+---------------------------------------+    |
#  |  ndmprotocol.h	| Protocol    (NDMJLP)  ndmp*.[chx]	| NDMJOBLIB
#  |  -			+---------------------------------------+    |
#  |			| SMC         (NDMJLS)  smc*.[ch]	|    |
#  |			| MD5         (NDMJL5)  md5*.[ch]	|    |
#  |			+---------------------------------------+    |
#  ndmos.h		| OS intf     (NDMJLO)  ndmos*.[ch]	|   /
#  -			+---------------------------------------+  /
#


#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_CONTROL_AGENT
#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_DATA_AGENT
#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_TAPE_AGENT
#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_ROBOT_AGENT
#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_NDMP2
#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_NDMP3
#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_NDMP4

#NDMOS_OPTIONS = -DNDMOS_OPTION_NO_NDMP3

# Set this if the autorecognizer in ndmos.h doesn't work
#NDMOS_ID = -DNDMOS_ID=NDMOS_ID_FREEBSD
#NDMOS_ID = -DNDMOS_ID=NDMOS_ID_SOLARIS
#NDMOS_ID = -DNDMOS_ID=NDMOS_ID_LINUX
#NDMOS_ID = -DNDMOS_ID=NDMOS_ID_XXX


#Generic
NDMOS_OPTIONS = -DNDMOS_CONST_NDMJOBLIB_REVISION='"(zmanda-2009)"'

#Linux
LIBS=
#LIBS= /home/ern/sources/DMALLOC/dmalloc-4.8.2/libdmalloc.a
DEFS = $(NDMOS_ID) $(NDMOS_OPTIONS)
AMCFLAGS = -g $(DEFS) -Wall -O -Werror -D_LARGEFILE64_SOURCE

#FreeBSD
#LIBS= -lcam
#DEFS = $(NDMOS_ID) $(NDMOS_OPTIONS)
#CFLAGS = -g $(DEFS) -Wall -O

#Solaris
#LIBS=-lsocket -lnsl
#DEFS = $(NDMOS_ID) $(NDMOS_OPTIONS)
#CFLAGS =  $(DEFS)

include $(top_srcdir)/config/automake/vars.am
include $(top_srcdir)/config/automake/installperms.am
include $(top_srcdir)/config/automake/precompile.am

LINT=$(AMLINT)
LINTFLAGS=$(AMLINTFLAGS)

LIB_EXTENSION = la

amlib_LTLIBRARIES =     libndmjla.la \
			libamndmp_backup_ndmjla.la \
			libndmjlr.la \
			libndmjll.la \
			libndmjlp.la \
			libndmjls.la \
			libndmjl5.la \
			libndmjlo.la

amlibexec_PROGRAMS = ndmjob amndmp_backup

INSTALLPERMS_exec = \
	dest=$(amlibexecdir) chown=amanda chmod= \
		$(amlibexec_PROGRAMS) \
	chown=root chmod=04750 \
		ndmjob amndmp_backup

libndmjla_la_SOURCES = \
	ndma_comm_job.c \
	ndma_comm_session.c \
	ndma_comm_dispatch.c \
	ndma_comm_subr.c \
	ndma_control.c \
	ndma_cops_backreco.c \
	ndma_cops_labels.c \
	ndma_cops_query.c \
	ndma_cops_robot.c \
	ndma_ctrl_calls.c \
	ndma_ctrl_conn.c \
	ndma_ctrl_media.c \
	ndma_ctrl_robot.c \
	ndma_ctst_tape.c \
	ndma_ctst_mover.c \
	ndma_ctst_data.c \
	ndma_ctst_subr.c \
	ndma_data.c \
	ndma_data_fh.c \
	ndma_data_pfe.c \
	ndma_image_stream.c \
	ndma_noti_calls.c \
	ndma_tape.c \
	ndma_tape_simulator.c \
	ndma_robot.c \
	wraplib.c

libamndmp_backup_ndmjla_la_SOURCES = \
	ndma_comm_job.c \
	ndma_comm_session.c \
	ndma_comm_dispatch.c \
	ndma_comm_subr.c \
	ndma_control.c \
	ndma_cops_backreco.c \
	ndma_cops_labels.c \
	ndma_cops_query.c \
	ndma_cops_robot.c \
	ndma_ctrl_calls.c \
	ndma_ctrl_conn.c \
	ndma_ctrl_media.c \
	ndma_ctrl_robot.c \
	ndma_ctst_tape.c \
	ndma_ctst_mover.c \
	ndma_ctst_data.c \
	ndma_ctst_subr.c \
	ndma_data.c \
	ndma_data_fh.c \
	ndma_data_pfe.c \
	ndma_image_stream.c \
	ndma_noti_calls.c \
	ndma_tape.c \
	amndmp_backup_tape_simulator.c \
	ndma_robot.c \
	wraplib.c

#libndmjob_la_SOURCES = \
#	ndmjob_main.c \
#	ndmjob_args.c \
#	ndmjob_job.c \
#	ndmjob_rules.c 

libndmjlr_la_SOURCES = \
	ndmjr_none.c
libndmjlr_la_LDFLAGS= -release $(VERSION)

libndmjll_la_SOURCES = \
	ndml_agent.c \
	ndml_bstf.c \
	ndml_chan.c \
	ndml_config.c \
	ndml_conn.c \
	ndml_cstr.c \
	ndml_log.c \
	ndml_md5.c \
	ndml_fhdb.c \
	ndml_fhh.c \
	ndml_media.c \
	ndml_nmb.c \
	ndml_scsi.c \
	ndml_stzf.c \
	ndml_util.c

libndmjlp_la_SOURCES = \
	ndmprotocol.c \
	ndmp_translate.c \
	ndmp2_translate.c ndmp3_translate.c ndmp4_translate.c \
	ndmp0_enum_strs.c ndmp0_pp.c ndmp0_xdr.c ndmp0_xmt.c \
	ndmp2_enum_strs.c ndmp2_pp.c ndmp2_xdr.c ndmp2_xmt.c \
	ndmp3_enum_strs.c ndmp3_pp.c ndmp3_xdr.c ndmp3_xmt.c \
	ndmp4_enum_strs.c ndmp4_pp.c ndmp4_xdr.c ndmp4_xmt.c \
	ndmp9_enum_strs.c            ndmp9_xdr.c ndmp9_xmt.c

libndmjls_la_SOURCES = \
	smc_api.c \
	smc_parse.c \
	smc_pp.c

libndmjl5_la_SOURCES = \
	md5c.c

#NDMJLO_SRCS = \
#	ndmos.h ndmos.c ndmos_common.c \
#	ndmos_solaris.h ndmos_solaris.c \
#	ndmos_freebsd.h ndmos_freebsd.c \
#	ndmos_linux.h ndmos_linux.c

#NDMJLO_OBJS = ndmos.o
libndmjlo_la_SOURCES = \
	ndmos.c

WRAP_TAR_OBJS = \
	wrap_tar.o \
	snoop_tar.o

WRAP_TEST_OBJS = \
	wrap_test.o

WRAPLIB_OBJS = \
	wraplib.o


WRAPLIB_SRCS = \
	wrap_comm_main.c \
	wrap_comm_args.c \
	wrap_comm_pfe.c \
	wrap_comm_msgio.c

WRAPLIB = wraplib.rel

NDMJOBLIB = \
	ndmjla.rel \
	ndmjlr.rel \
	ndmjll.rel \
	ndmjlp.rel \
	ndmjls.rel \
	ndmjl5.rel \
	ndmjlo.rel

AMNDMP_BACKUP_LIB = \
	amndmp_backup_ndmjla.rel \
	ndmjlr.rel \
	ndmjll.rel \
	ndmjlp.rel \
	ndmjls.rel \
	ndmjl5.rel \
	ndmjlo.rel


#all: ndmjob wrap_tar wrap_test icheck amndmp_backup
all: ndmjob amndmp_backup

ndmjob_SOURCES = ndmjob_main.c \
		 ndmjob_args.c \
		 ndmjob_job.c \
		 ndmjob_rules.c

amndmp_backup_SOURCES = ndmjob_main.c \
			ndmjob_args.c \
			ndmjob_job.c \
			ndmjob_rules.c

ndmjob_LDADD = \
	libndmjla.la \
	libndmjlr.la \
	libndmjll.la \
	libndmjlp.la \
	libndmjls.la \
	libndmjl5.la \
	libndmjlo.la
	
amndmp_backup_LDADD = \
	libamndmp_backup_ndmjla.la \
	libndmjlr.la \
	libndmjll.la \
	libndmjlp.la \
	libndmjls.la \
	libndmjl5.la \
	libndmjlo.la
	
#ndmjob_main.o: ndmjob.h
#
#ndmjob: $(NDMJOB_OBJS) $(NDMJOBLIB)
#	cc -o ndmjob  $(NDMJOB_OBJS) $(NDMJOBLIB) $(LIBS)
#
#amndmp_backup: $(NDMJOB_OBJS) $(AMNDMP_BACKUP_LIB)
#	cc -o amndmp_backup  $(NDMJOB_OBJS) $(AMNDMP_BACKUP_LIB) $(LIBS)

#ndmjoblib: $(NDMJOBLIB)


#ndmjla.rel : $(NDMJLA_OBJS)
#	ld -r -o ndmjla.rel $(NDMJLA_OBJS)

#amndmp_backup_ndmjla.rel : $(AMNDMP_BACKUP_NDMJLA_OBJS)
#	ld -r -o amndmp_backup_ndmjla.rel $(AMNDMP_BACKUP_NDMJLA_OBJS)

#ndmjlr.rel : $(NDMJLR_OBJS)
#	ld -r -o ndmjlr.rel $(NDMJLR_OBJS)

#ndmjll.rel : $(NDMJLL_OBJS)
#	ld -r -o ndmjll.rel $(NDMJLL_OBJS)

#ndmjlp.rel : $(NDMJLP_OBJS)
#	ld -r -o ndmjlp.rel $(NDMJLP_OBJS)

#ndmjls.rel : $(NDMJLS_OBJS)
#	ld -r -o ndmjls.rel $(NDMJLS_OBJS)

#ndmjl5.rel : $(NDMJL5_OBJS)
#	ld -r -o ndmjl5.rel $(NDMJL5_OBJS)

#ndmjlo.rel : $(NDMJLO_OBJS)
#	ld -r -o ndmjlo.rel $(NDMJLO_OBJS)

#$(NDMJLO_OBJS) : $(NDMJLO_SRCS)




#
# The NDMJOBLIB is dropped with rpcgen(1) results.
# You shouldn't have to re-run rpcgen(1) unless
# you change something, which is rarely a good idea.
#
ndmp_prot :
	$(MAKE) ndmp0.h ndmp2.h ndmp3.h ndmp4.h ndmp9.h

ndmp0.h ndmp0_xdr.c : ndmp0.x
	rpcgen ndmp0.x

ndmp2.h ndmp2_xdr.c : ndmp2.x
	rpcgen ndmp2.x

ndmp3.h ndmp3_xdr.c : ndmp3.x
	rpcgen ndmp3.x

ndmp4.h ndmp4_xdr.c : ndmp4.x
	rpcgen ndmp4.x

ndmp9.h ndmp9_xdr.c : ndmp9.x
	rpcgen ndmp9.x

wrap_tar: $(WRAP_TAR_OBJS) wraplib.o
	cc -o wrap_tar $(WRAP_TAR_OBJS) wraplib.o $(LIBS)

wrap_test: $(WRAP_TEST_OBJS) wraplib.o
	cc -o wrap_test $(WRAP_TEST_OBJS) wraplib.o $(LIBS)

wraplib.o : wraplib.c wraplib.h ndmos.h

$(WRAP_TAR_OBJS) : wraplib.h ndmos.h


smccmd: smccmd.o $(NDMJLS_OBJS)
	cc -o smccmd smccmd.o $(NDMJLS_OBJS) $(LIBS)


wt1: wt1.o wraplib.o
	cc -o wt1 wt1.o wraplib.o

icheck.c: ndml_fhdb.c 
	cp ndml_fhdb.c icheck.c

icheck: icheck.c
	cc ${CFLAGS} -o icheck -DSELF_TEST icheck.c


#clean:
#	rm -f *.o *.rel ndmjob *.core icheck icheck.c
#	rm -f wrap_tar wrap_test
#
#veryclean:
#	rm -f ndmp0.h ndmp0_xdr.c
#	rm -f ndmp2.h ndmp2_xdr.c
#	rm -f ndmp3.h ndmp3_xdr.c
#	rm -f ndmp4.h ndmp4_xdr.c
#	rm -f ndmp9.h ndmp9_xdr.c
#	rm -f *.o *.rel *.core
#	rm -f ndmjob wrap_tar wrap_dump wrap_test

noinst_HEADERS = \
	md5.h            ndmp0_enum_strs.h  ndmp3.x            ndmprotocol.h \
	ndmagents.h      ndmp0.h            ndmp4_enum_strs.h  ndmp_translate.h \
	ndmjob.h         ndmp0.x            ndmp4.h            scsiconst.h \
	ndmjr_none.h     ndmp2_enum_strs.h  ndmp4_translate.h  smc.h \
	ndmlib.h         ndmp2.h            ndmp4.x            smc_priv.h \
	ndmos_freebsd.h  ndmp2_translate.h  ndmp9_enum_strs.h  smc_raw.h \
	ndmos.h          ndmp2.x            ndmp9.h            snoop_tar.h \
	ndmos_linux.h    ndmp3_enum_strs.h  ndmp9.x            tarhdr_gnu.h \
	ndmos_solaris.h  ndmp3.h            ndmp_ammend.h      wraplib.h \
	ndmos_xxx.h      ndmp3_translate.h  ndmp_msg_buf.h \
	ndmos_linux.c    ndmos_freebsd.c    ndmos_solaris.c    ndmos_xxx.c \
	ndmos_common.c
