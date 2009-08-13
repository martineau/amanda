/*
 * Copyright (c) 2008,2009 Zmanda, Inc.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Contact information: Zmanda Inc., 465 N Mathlida Ave, Suite 300
 * Sunnyvale, CA 94085, USA, or: http://www.zmanda.com
 */

/* An Ndmp device uses Amazon's Ndmp service (http://www.amazon.com/ndmp) to store
 * data.  It stores data in keys named with a user-specified prefix, inside a
 * user-specified bucket.  Data is stored in the form of numbered (large)
 * blocks.
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <regex.h>
#include <time.h>
#include "util.h"
#include "amanda.h"
#include "conffile.h"
#include "device.h"
//#include "ndmp.h"
#include <curl/curl.h>
#ifdef HAVE_OPENSSL_HMAC_H
# include <openssl/hmac.h>
#else
# ifdef HAVE_CRYPTO_HMAC_H
#  include <crypto/hmac.h>
# else
#  ifdef HAVE_HMAC_H
#   include <hmac.h>
#  endif
# endif
#endif

#include "stream.c"
#include "ndmp-protocol.h"

/*
 * Type checking and casting macros
 */
#define TYPE_NDMP_DEVICE	(ndmp_device_get_type())
#define NDMP_DEVICE(obj)	G_TYPE_CHECK_INSTANCE_CAST((obj), ndmp_device_get_type(), NdmpDevice)
#define NDMP_DEVICE_CONST(obj)	G_TYPE_CHECK_INSTANCE_CAST((obj), ndmp_device_get_type(), NdmpDevice const)
#define NDMP_DEVICE_CLASS(klass)	G_TYPE_CHECK_CLASS_CAST((klass), ndmp_device_get_type(), NdmpDeviceClass)
#define IS_NDMP_DEVICE(obj)	G_TYPE_CHECK_INSTANCE_TYPE((obj), ndmp_device_get_type ())

#define NDMP_DEVICE_GET_CLASS(obj)	G_TYPE_INSTANCE_GET_CLASS((obj), ndmp_device_get_type(), NdmpDeviceClass)
static GType	ndmp_device_get_type	(void);

/*
 * Main object structure
 */
typedef struct _NdmpMetadataFile NdmpMetadataFile;

typedef struct _NdmpDevice NdmpDevice;
struct _NdmpDevice {
    Device __parent__;

    amprotocol_t *protocol; /* to ndmp-proxy */
    int           open;     /* if a device is open */
    char         *device_name;

    /* Produce verbose output? */
    gboolean verbose;
};

/*
 * Class definition
 */
typedef struct _NdmpDeviceClass NdmpDeviceClass;
struct _NdmpDeviceClass {
    DeviceClass __parent__;
};


/*
 * Constants and static data
 */

#define NDMP_DEVICE_NAME "ndmp"

/* Maximum key length as specified in the Ndmp documentation
 * (*excluding* null terminator) */
#define Ndmp_MAX_KEY_LENGTH 1024

/* Note: for compatability, min can only be decreased and max increased */
#define NDMP_DEVICE_MIN_BLOCK_SIZE 1024
#define NDMP_DEVICE_MAX_BLOCK_SIZE (100*1024*1024)
#define NDMP_DEVICE_DEFAULT_BLOCK_SIZE (10*1024*1024)

/* This goes in lieu of file number for metadata. */
#define SPECIAL_INFIX "special-"

/* pointer to the class of our parent */
static DeviceClass *parent_class = NULL;

/*
 * device-specific properties
 */

/*
 * prototypes
 */

void ndmp_device_register(void);

/*
 * utility functions */

static gboolean
write_amanda_header(NdmpDevice *nself,
                    char *label,
                    char * timestamp);
static int ndmp_mtio_eod(NdmpDevice *nself);
static int ndmp_mtio_eof(NdmpDevice *nself);
static int ndmp_mtio_rewind(NdmpDevice *nself);
static int ndmp_mtio(NdmpDevice *nself, char *cmd, int count);
static int ndmp_device_robust_write(NdmpDevice *nself, char *buf, int count, char **ermsg);

/* "Fast forward" this device to the end by looking up the largest file number
 * present and setting the current file number one greater.
 *
 * @param nself: the NdmpDevice object
 */
static gboolean
seek_to_end(NdmpDevice *nself);

/* Find the number of the last file that contains any data (even just a header).
 *
 * @param nself: the NdmpDevice object
 * @returns: the last file, or -1 in event of an error
 */
static int
find_last_file(NdmpDevice *nself);

/* Delete all blocks in the given file, including the filestart block
 *
 * @param nself: the NdmpDevice object
 * @param file: the file to delete
 */
static gboolean
delete_file(NdmpDevice *nself,
            int file);


/* Delete all files in the given device
 *
 * @param nself: the NdmpDevice object
 */
static gboolean
delete_all_files(NdmpDevice *nself);

/* Set up nself->ndmp as best as possible.
 *
 * The return value is TRUE iff nself->ndmp is useable.
 *
 * @param nself: the NdmpDevice object
 * @returns: TRUE if the handle is set up
 */
static gboolean
setup_handle(NdmpDevice * nself);

/*
 * class mechanics */

static void
ndmp_device_init(NdmpDevice * o);

static void
ndmp_device_class_init(NdmpDeviceClass *c);

static void
ndmp_device_finalize(GObject *o);

static Device*
ndmp_device_factory(char *device_name, char *device_type, char *device_node);

/*
 * Property{Get,Set}Fns */

static gboolean ndmp_device_set_verbose_fn(Device *dself,
    DevicePropertyBase *base, GValue *val,
    PropertySurety surety, PropertySource source);

/*
 * virtual functions */

static void
ndmp_device_open_device(Device *dself, char *device_name,
		  char * device_type, char * device_node);

static DeviceStatusFlags ndmp_device_read_label(Device *dself);

static gboolean
ndmp_device_start(Device *dself,
                DeviceAccessMode mode,
                char * label,
                char * timestamp);

static gboolean
ndmp_device_finish(Device *dself);

static gboolean
ndmp_device_start_file(Device *dself,
                     dumpfile_t * jobInfo);

static gboolean
ndmp_device_write_block(Device *dself,
                      guint size,
                      gpointer data);

static gboolean
ndmp_device_finish_file(Device *dself);

static dumpfile_t*
ndmp_device_seek_file(Device *dself,
                    guint file);

static gboolean
ndmp_device_seek_block(Device *dself,
                     guint64 block);

static int
ndmp_device_read_block(Device * dself,
                     gpointer data,
                     int *size_req);

static gboolean
ndmp_device_recycle_file(Device *dself,
                       guint file);

static gboolean
ndmp_device_erase(Device *dself);

/*
 * Private functions
 */

static gboolean
write_amanda_header(NdmpDevice *nself,
                    char *label,
                    char * timestamp)
{
    char * amanda_header = NULL;
    char * key = NULL;
    gboolean result;
    dumpfile_t * dumpinfo = NULL;
    Device *dself = DEVICE(nself);
    size_t header_size;


    /* build the header */
    header_size = 0; /* no minimum size */
    dumpinfo = make_tapestart_header(dself, label, timestamp);
    amanda_header = device_build_amanda_header(dself, dumpinfo,
        &header_size);
    if (amanda_header == NULL) {
	device_set_error(dself,
	    stralloc(_("Amanda tapestart header won't fit in a single block!")),
	    DEVICE_STATUS_DEVICE_ERROR);
	g_free(amanda_header);
	return FALSE;
    }

    /* write out the header and flush the uploads. */
//    key = special_file_to_key(nself, "tapestart", -1);
    g_assert(header_size < G_MAXUINT); /* for cast to guint */
//    result = ndmp_upload(nself->ndmp, nself->bucket, key, Ndmp_BUFFER_READ_FUNCS,
//                       &amanda_header, NULL, NULL);
    g_free(amanda_header);
    g_free(key);

    if (!result) {
	device_set_error(dself,
	    //vstrallocf(_("While writing amanda header: %s"), ndmp_strerror(nself->ndmp)),
	    vstrallocf(_("While writing amanda header: %s"), "ndmp_strerror"),
	    DEVICE_STATUS_DEVICE_ERROR | DEVICE_STATUS_VOLUME_ERROR);
    }
    return result;
}

static gboolean
seek_to_end(NdmpDevice *nself) {
    int last_file;

    Device *dself = DEVICE(nself);

    last_file = find_last_file(nself);
    if (last_file < 0)
        return FALSE;

    dself->file = last_file;

    return TRUE;
}

/* Find the number of the last file that contains any data (even just a header).
 * Returns -1 in event of an error
 */
static int
find_last_file(NdmpDevice *nself) {
    nself = nself;
}

/* Find the number of the file following the requested one, if any.
 * Returns 0 if there is no such file or -1 in event of an error
 */
static int
find_next_file(NdmpDevice *nself, int last_file) {
    nself = nself;
    last_file = last_file;

    return 0;
}

static gboolean
delete_file(NdmpDevice *nself,
            int file)
{
    nself = nself;
    file = file;

    return TRUE;
}

static gboolean
delete_all_files(NdmpDevice *nself)
{
    nself = nself;

    return TRUE;
}

/*
 * Class mechanics
 */

void
ndmp_device_register(void)
{
    static const char * device_prefix_list[] = { NDMP_DEVICE_NAME, NULL };

    /* register the device itself */
    register_device(ndmp_device_factory, device_prefix_list);
}

static GType
ndmp_device_get_type(void)
{
    static GType type = 0;

    if G_UNLIKELY(type == 0) {
        static const GTypeInfo info = {
            sizeof (NdmpDeviceClass),
            (GBaseInitFunc) NULL,
            (GBaseFinalizeFunc) NULL,
            (GClassInitFunc) ndmp_device_class_init,
            (GClassFinalizeFunc) NULL,
            NULL /* class_data */,
            sizeof (NdmpDevice),
            0 /* n_preallocs */,
            (GInstanceInitFunc) ndmp_device_init,
            NULL
        };

        type = g_type_register_static (TYPE_DEVICE, "NdmpDevice", &info,
                                       (GTypeFlags)0);
    }

    return type;
}

static void
ndmp_device_init(NdmpDevice *nself)
{
    Device *dself = DEVICE(nself);
    GValue response;

    nself->protocol = NULL;
    nself->open = 0;

    /* Register property values
     * Note: Some aren't added until ndmp_device_open_device()
     */
    bzero(&response, sizeof(response));

    g_value_init(&response, CONCURRENCY_PARADIGM_TYPE);
    g_value_set_enum(&response, CONCURRENCY_PARADIGM_SHARED_READ);
    device_set_simple_property(dself, PROPERTY_CONCURRENCY,
	    &response, PROPERTY_SURETY_GOOD, PROPERTY_SOURCE_DETECTED);
    g_value_unset(&response);

    g_value_init(&response, STREAMING_REQUIREMENT_TYPE);
    g_value_set_enum(&response, STREAMING_REQUIREMENT_NONE);
    device_set_simple_property(dself, PROPERTY_STREAMING,
	    &response, PROPERTY_SURETY_GOOD, PROPERTY_SOURCE_DETECTED);
    g_value_unset(&response);

    g_value_init(&response, G_TYPE_BOOLEAN);
    g_value_set_boolean(&response, TRUE);
    device_set_simple_property(dself, PROPERTY_APPENDABLE,
	    &response, PROPERTY_SURETY_GOOD, PROPERTY_SOURCE_DETECTED);
    g_value_unset(&response);

    g_value_init(&response, G_TYPE_BOOLEAN);
    g_value_set_boolean(&response, TRUE);
    device_set_simple_property(dself, PROPERTY_PARTIAL_DELETION,
	    &response, PROPERTY_SURETY_GOOD, PROPERTY_SOURCE_DETECTED);
    g_value_unset(&response);

    g_value_init(&response, G_TYPE_BOOLEAN);
    g_value_set_boolean(&response, TRUE);
    device_set_simple_property(dself, PROPERTY_FULL_DELETION,
	    &response, PROPERTY_SURETY_GOOD, PROPERTY_SOURCE_DETECTED);
    g_value_unset(&response);

    g_value_init(&response, MEDIA_ACCESS_MODE_TYPE);
    g_value_set_enum(&response, MEDIA_ACCESS_MODE_READ_WRITE);
    device_set_simple_property(dself, PROPERTY_MEDIUM_ACCESS_TYPE,
	    &response, PROPERTY_SURETY_GOOD, PROPERTY_SOURCE_DETECTED);
    g_value_unset(&response);

}

static void
ndmp_device_class_init(NdmpDeviceClass * c G_GNUC_UNUSED)
{
    GObjectClass *g_object_class = (GObjectClass*) c;
    DeviceClass *device_class = (DeviceClass *)c;

    parent_class = g_type_class_ref (TYPE_DEVICE);

    device_class->open_device = ndmp_device_open_device;
    device_class->read_label = ndmp_device_read_label;
    device_class->start = ndmp_device_start;
    device_class->finish = ndmp_device_finish;

    device_class->start_file = ndmp_device_start_file;
    device_class->write_block = ndmp_device_write_block;
    device_class->finish_file = ndmp_device_finish_file;

    device_class->seek_file = ndmp_device_seek_file;
    device_class->seek_block = ndmp_device_seek_block;
    device_class->read_block = ndmp_device_read_block;
    device_class->recycle_file = ndmp_device_recycle_file;

    device_class->erase = ndmp_device_erase;

    g_object_class->finalize = ndmp_device_finalize;

    device_class_register_property(device_class, PROPERTY_VERBOSE,
	    PROPERTY_ACCESS_GET_MASK | PROPERTY_ACCESS_SET_BEFORE_START,
	    device_simple_property_get_fn,
	    ndmp_device_set_verbose_fn);
}

static gboolean
ndmp_device_set_verbose_fn(Device *dself, DevicePropertyBase *base,
    GValue *val, PropertySurety surety, PropertySource source)
{
    NdmpDevice *nself = NDMP_DEVICE(dself);

    nself->verbose = g_value_get_boolean(val);
    /* Our Ndmp handle may not yet have been instantiated; if so, it will
     * get the proper verbose setting when it is created */
//    if (nself->ndmp)
//	ndmp_verbose(nself->ndmp, self->verbose);

    return device_simple_property_set_fn(dself, base, val, surety, source);
}

static Device*
ndmp_device_factory(
    char *device_name,
    char *device_type,
    char *device_node)
{
    Device *rval;
    NdmpDevice * ndmp_rval;
    g_assert(0 == strcmp(device_type, NDMP_DEVICE_NAME));
    rval = DEVICE(g_object_new(TYPE_NDMP_DEVICE, NULL));
    ndmp_rval = (NdmpDevice *)rval;

    device_open_device(rval, device_name, device_type, device_node);
    return rval;
}

/*
 * Virtual function overrides
 */

static int
try_open_ndmp_device(
    NdmpDevice *nself,
    char       *device_filename)
{
    Device              *dself = DEVICE(nself);
    int                  rc;
    amprotocol_packet_t *c_packet;
    char                *error_str;

dbprintf("try_open_ndmp_device 1\n");
    rc = amprotocol_send_list(nself->protocol, CMD_TAPE_OPEN, 4,
					device_filename, "RDWR",
					"localhost", "4,ndmp,ndmp");
    if (rc <= 0) {
	device_set_error(dself,
			 _("failed to write CMD_TAPE_OPEN to ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	return -1;
    }
    dbprintf("Sent CMD_TAPE_OPEN to ndmp-proxy\n");

    c_packet = amprotocol_get(nself->protocol);
    if (!c_packet) {
	device_set_error(dself, _("B failed to get a packet from ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	return -1;
    }
    dbprintf("get packet from ndmp-proxy\n");
    if (c_packet->command != REPLY_TAPE_OPEN) {
	device_set_error(dself,
			 _("failed to get a REPLY_TAPE_OPEN from ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	free_amprotocol_packet(c_packet);
	return -1;
    }

    error_str = c_packet->arguments[0].data;
    dbprintf("e %s\n", error_str);
    if (strcmp(error_str, "NDMP9_NO_ERR") != 0) {
	device_set_error(dself,
			 vstrallocf(_("REPLY_TAPE_OPEN failed: %s"), error_str),
			 DEVICE_STATUS_DEVICE_ERROR);
	free_amprotocol_packet(c_packet);
	return -1;
    }
    free_amprotocol_packet(c_packet);
    dbprintf("get REPLY_TAPE_OPEN packet from ndmp-proxy\n");
    return 0;
}

static void
ndmp_device_open_device(
    Device *dself,
    char   *device_name,
    char   *device_type,
    char   *device_node)
{
    NdmpDevice          *nself = NDMP_DEVICE(dself);
    int                  rc;
    amprotocol_packet_t *c_packet;
    int                  fd;

dbprintf("ndmp_device_open_device: %s : %s : %s\n", device_name, device_type, device_node);
    nself->protocol = malloc(sizeof(listen_ndmp));
    memmove(nself->protocol, &listen_ndmp, sizeof(listen_ndmp));
    fd = stream_client("localhost", 2345, 32768, 32768, NULL, 0);
    nself->protocol->fd = fd;
    nself->device_name = stralloc(device_node);

dbprintf("connected to ndmp-proxy: %d\n", nself->protocol->fd);
    rc = amprotocol_send_list(nself->protocol, CMD_DEVICE, 0);
    if (rc <= 0) {
	device_set_error(dself, _("failed to write CMD_DEVICE to ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	return;
    }
    dbprintf("Sent CMD_DEVICE to ndmp-proxy\n");

    c_packet = amprotocol_get(nself->protocol);
    dbprintf("get packet from ndmp-proxy 1\n");
    if (!c_packet) {
	device_set_error(dself, vstrallocf(_("A failed to get a packet from ndmp-proxy: %s"), strerror(errno)),
			 DEVICE_STATUS_DEVICE_ERROR);
	return;
    }
    if (c_packet->command != REPLY_DEVICE) {
	device_set_error(dself, _("failed to get a REPLY_DEVICE from ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	free_amprotocol_packet(c_packet);
	return;
    }
    dbprintf("got REPLY_DEVICE from ndmp-proxy\n");

    if (strcmp(c_packet->arguments[0].data, "NDMP9_NO_ERR") != 0) {
	device_set_error(dself,
		vstrallocf(_("%s"), c_packet->arguments[0].data),
		  DEVICE_STATUS_DEVICE_ERROR);
	free_amprotocol_packet(c_packet);
	return;
    }

    amfree(nself->protocol);
    nself->protocol = malloc(sizeof(device_ndmp));
    memmove(nself->protocol, &device_ndmp, sizeof(device_ndmp));
    nself->protocol->fd = fd;

    if (parent_class->open_device) {
        parent_class->open_device(dself, device_name, device_type, device_node);
    }
}

static void ndmp_device_finalize(GObject * obj_self)
{
    NdmpDevice       *nself = NDMP_DEVICE (obj_self);
    int               rc;
    amprotocol_packet_t *c_packet;

    if(G_OBJECT_CLASS(parent_class)->finalize)
        (* G_OBJECT_CLASS(parent_class)->finalize)(obj_self);

    rc = amprotocol_send_list(nself->protocol, CMD_TAPE_CLOSE, 0);
    if (rc <= 0) {
	dbprintf(_("failed to write CMD_TAPE_CLOSE to ndmp-proxy"));
	goto finalize;
    }
    dbprintf("Sent CMD_TAPE_CLOSE to ndmp-proxy\n");

    c_packet = amprotocol_get(nself->protocol);
    if (!c_packet) {
	dbprintf(_("failed to get a packet from ndmp-proxy"));
	goto finalize;
    }
    dbprintf("get packet from ndmp-proxy\n");
    if (c_packet->command != REPLY_TAPE_CLOSE) {
	dbprintf(_("failed to get a REPLY_TAPE_CLOSE from ndmp-proxy: %d\n"), c_packet->command);
	goto finalize;
    }
    dbprintf("get REPLY_TAPE_CLOSE packet from ndmp-proxy\n");

finalize:
dbprintf("finalize aa\n");
    nself->open = 0;
dbprintf("finalize bb\n");
    robust_close(nself->protocol->fd);
dbprintf("finalize cc\n");
    amfree(nself->protocol);
dbprintf("finalize dd\n");
}

static gboolean setup_handle(
    NdmpDevice *nself)
{
    Device *dself = DEVICE(nself);
    dself = dself;
}

static DeviceStatusFlags
ndmp_device_read_label(
    Device *dself)
{
    NdmpDevice       *nself = NDMP_DEVICE(dself);
    //char             *header_buffer;
    dumpfile_t       *header;
    int               rc;
    int               count;
    amprotocol_packet_t *c_packet;

    amfree(dself->volume_label);
    amfree(dself->volume_time);
    amfree(dself->volume_header);

    if (device_in_error(nself)) return dself->status;

    header = dself->volume_header = g_new(dumpfile_t, 1);
    fh_init(header);

    if (!nself->open) {
dbprintf("A ndmp_device_read_label: try_open_ndmp_device: %d\n", rc);
	rc = try_open_ndmp_device(nself, nself->device_name);
dbprintf("B ndmp_device_read_label: try_open_ndmp_device: %d\n", rc);
	if (rc == -1) {
dbprintf("C ndmp_device_read_label: try_open_ndmp_device: %d %d\n", rc, dself->status);
	    return dself->status;
	}
	nself->open = 1;
    }

    /* Rewind it. */
    if (!ndmp_mtio_rewind(nself)) {
	return dself->status;
    }

    count = 32768;
    amprotocol_send_binary(nself->protocol, CMD_TAPE_READ, 1, sizeof(int), &count);
    c_packet = amprotocol_get(nself->protocol);
    if (!c_packet) { exit(1); };
    if (c_packet->command != REPLY_TAPE_READ) { exit(1); };

    if (strcmp(c_packet->arguments[0].data, "NDMP9_EOF_ERR") == 0) {
	device_set_error(dself,
		g_strdup(_("unlabeled volume")), DEVICE_STATUS_VOLUME_UNLABELED);
	free_amprotocol_packet(c_packet);
	return dself->status;
    } else if (strcmp(c_packet->arguments[0].data, "NDMP9_NO_ERR") != 0) {
	device_set_error(dself,
		vstrallocf(_("Unknown error: %s"), c_packet->arguments[0].data),
		  DEVICE_STATUS_DEVICE_ERROR
		| DEVICE_STATUS_VOLUME_ERROR);
	free_amprotocol_packet(c_packet);
	return dself->status;
    }

    parse_file_header(c_packet->arguments[1].data, header, c_packet->arguments[1].size);
    free_amprotocol_packet(c_packet);
    if (header->type != F_TAPESTART) {
	device_set_error(dself,
		stralloc(_("No tapestart header -- unlabeled device?")),
			 DEVICE_STATUS_VOLUME_UNLABELED);
	return dself->status;
    }
    dself->volume_label = g_strdup(header->name);
    dself->volume_time = g_strdup(header->datestamp);
    /* dself->volume_header is already set */

    device_set_error(dself, NULL, DEVICE_STATUS_SUCCESS);

    return dself->status;
}

/* Just a helper function for ndmp_device_start(). */
static gboolean
write_tapestart_header(
    NdmpDevice *nself,
    char       *label,
    char       *timestamp)
{
    int         result;
    Device     *dself = (Device*)nself;
    dumpfile_t *header;
    char       *header_buf;
    char       *msg = NULL;

dbprintf("write_tapestart_header 1\n");
    if (!ndmp_mtio_rewind(nself)) {
	return FALSE;
    }
dbprintf("write_tapestart_header 2\n");

    header = make_tapestart_header(dself, label, timestamp);
dbprintf("write_tapestart_header 3\n");
    g_assert(header != NULL);
    header_buf = device_build_amanda_header(dself, header, NULL);
dbprintf("write_tapestart_header 4\n");
    if (header_buf == NULL) {
dbprintf("write_tapestart_header 5\n");
	device_set_error(dself,
	    stralloc(_("Tapestart header won't fit in a single block!")),
	    DEVICE_STATUS_DEVICE_ERROR);
	return FALSE;
    }
dbprintf("write_tapestart_header 6\n");
    amfree(header);

    result = ndmp_device_robust_write(nself, header_buf, dself->block_size, &msg);
dbprintf("write_tapestart_header 7\n");
    if (!result) {
dbprintf("write_tapestart_header 8\n");
	device_set_error(dself, 
	    g_strdup_printf(_("Error writing tapestart header: %s"), msg),
	    DEVICE_STATUS_DEVICE_ERROR);
	amfree(msg);
	amfree(header_buf);
	return FALSE;
    }

dbprintf("write_tapestart_header 9\n");
    amfree(header_buf);
    if (!ndmp_mtio_eof(nself)) {
dbprintf("write_tapestart_header 10\n");
	device_set_error(dself,
			 vstrallocf(_("Error writing filemark: %s"),
				    strerror(errno)),
			 DEVICE_STATUS_DEVICE_ERROR|DEVICE_STATUS_VOLUME_ERROR);
	return FALSE;
    }
dbprintf("write_tapestart_header 11\n");

    return TRUE;
}


static gboolean
ndmp_device_start(
    Device           *dself,
    DeviceAccessMode  mode,
    char             *label,
    char             *timestamp)
{
    NdmpDevice *nself = NDMP_DEVICE(dself);

    nself = NDMP_DEVICE(dself);

    if (device_in_error(nself)) return FALSE;

    if (!nself->open) {
dbprintf("ndmp_device_start 1\n");
	try_open_ndmp_device(nself, nself->device_name);
dbprintf("ndmp_device_start 2 %d\n", nself->protocol->fd);
	if (!nself->open)
	    return FALSE;
    }

    if (mode != ACCESS_WRITE && dself->volume_label == NULL) {
	if (ndmp_device_read_label(dself) != DEVICE_STATUS_SUCCESS)
dbprintf("ndmp_device_start: ndmp_device_read_label: failed\n");
	    return FALSE;
    }

    dself->access_mode = mode;
    dself->in_file = FALSE;

    if (IS_WRITABLE_ACCESS_MODE(mode)) {
	//if (self->write_open_errno != 0) {
	//} else
	if (!ndmp_mtio_rewind(nself)) {
	    return FALSE;
	}
    }

    /* Position the tape */
    switch (mode) {
    case ACCESS_APPEND:
	if (dself->volume_label == NULL && device_read_label(dself) != DEVICE_STATUS_SUCCESS) {
	    /* device_read_label already set our error message */
	    return FALSE;
	}

	if (!ndmp_mtio_eod(nself)) {
//	    device_set_error(dself,
//		vstrallocf(_("Couldn't seek to end of tape: %s"), strerror(errno)),
//		DEVICE_STATUS_DEVICE_ERROR);
	    return FALSE;
	}
	break;

    case ACCESS_READ:
	if (dself->volume_label == NULL && device_read_label(dself) != DEVICE_STATUS_SUCCESS) {
	    /* device_read_label already set our error message */
	    return FALSE;
	}

	if (!ndmp_mtio_rewind(nself)) {
	    return FALSE;
	}
	dself->file = 0;
	break;

    case ACCESS_WRITE:
	if (!write_tapestart_header(nself, label, timestamp)) {
	    /* write_tapestart_header already set the error status */
	    return FALSE;
	}

	dself->volume_label = newstralloc(dself->volume_label, label);
	dself->volume_time = newstralloc(dself->volume_time, timestamp);

	/* unset the VOLUME_UNLABELED flag, if it was set */
	device_set_error(dself, NULL, DEVICE_STATUS_SUCCESS);
	dself->file = 0;
	break;

    default:
	g_assert_not_reached();
    }

    return TRUE;
}

static gboolean
ndmp_device_finish(
    Device *dself)
{
    if (device_in_error(dself)) return FALSE;

    /* we're not in a file anymore */
    dself->access_mode = ACCESS_NULL;

    return TRUE;
}

/* functions for writing */


static gboolean
ndmp_device_start_file(
    Device     *dself,
    dumpfile_t *jobInfo)
{
    NdmpDevice *self = NDMP_DEVICE(dself);

    self = self;
    jobInfo = jobInfo;

    return TRUE;
}

static gboolean
ndmp_device_write_block(
    Device   *dself,
    guint     size,
    gpointer  data)
{
    NdmpDevice *nself = NDMP_DEVICE(dself);
    nself = nself;
    size = size;
    data = data;

    return TRUE;
}

static gboolean
ndmp_device_finish_file(
    Device *dself)
{
    if (device_in_error(dself)) return FALSE;

    /* we're not in a file anymore */
    dself->in_file = FALSE;

    return TRUE;
}

static gboolean
ndmp_device_recycle_file(
    Device *dself,
    guint   file)
{
    NdmpDevice *self = NDMP_DEVICE(dself);
    if (device_in_error(self)) return FALSE;

    return delete_file(self, file);
    /* delete_file already set our error message if necessary */
}

static gboolean
ndmp_device_erase(
    Device *dself)
{
    NdmpDevice *nself = NDMP_DEVICE(dself);
    nself = nself;

    return TRUE;
}

/* functions for reading */

static dumpfile_t*
ndmp_device_seek_file(
    Device *dself,
    guint   file)
{
    NdmpDevice *nself = NDMP_DEVICE(dself);

    nself = nself;
    file = file;

    return NULL;
}

static gboolean
ndmp_device_seek_block(
    Device  *dself,
    guint64  block)
{
    if (device_in_error(dself)) return FALSE;

    dself->block = block;
    return TRUE;
}

typedef struct ndmp_read_block_data {
    gpointer data;
    int size_req;
    int size_written;

} ndmp_read_block_data;

/* wrapper around ndmp_buffer_write_func to write as much data as possible to
 * the user's buffer, and switch to a dynamically allocated buffer if that
 * isn't large enough */
static size_t
ndmp_read_block_write_func(void *ptr, size_t size, size_t nmemb, void *stream)
{
    ptr = ptr;
    size = size;
    nmemb = nmemb;
    stream = stream;

    return 0;
}

static int
ndmp_device_read_block (Device * dself, gpointer data, int *size_req) {
    NdmpDevice *nself = NDMP_DEVICE(dself);
    nself = nself;
    data = data;
    size_req = size_req;

    return 0;
}

static int
ndmp_mtio_eod(
    NdmpDevice *nself)
{
    return ndmp_mtio(nself, "EOD", 1);
}

static int
ndmp_mtio_eof(
    NdmpDevice *nself)
{
    return ndmp_mtio(nself, "EOF", 1);
}

static int
ndmp_mtio_rewind(
    NdmpDevice *nself)
{
    return ndmp_mtio(nself, "REWIND", 1);
}

static int
ndmp_mtio(
    NdmpDevice *nself,
    char       *cmd,
    int         count)
{
    Device           *dself = DEVICE(nself);
    int               rc;
    amprotocol_packet_t *c_packet;
    char             *error_str;
    char             *count_str = g_strdup_printf("%d", count);

    rc = amprotocol_send_list(nself->protocol, CMD_TAPE_MTIO, 2, cmd, count_str);
    amfree(count_str);
    if (rc <= 0) {
	device_set_error(dself,
			 vstrallocf(_("failed to write CMD_TAPE_MTIO %s to ndmp-proxy"), cmd),
			   DEVICE_STATUS_DEVICE_ERROR
			 | DEVICE_STATUS_VOLUME_ERROR);
        return FALSE;
    }
    dbprintf("Sent CMD_TAPE_MTIO %s to ndmp-proxy\n", cmd);

    c_packet = amprotocol_get(nself->protocol);
    if (!c_packet) {
	device_set_error(dself, _("failed to get a REPLY_TAPE_MTIO packet from ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	return FALSE;
    }
    dbprintf("get packet from ndmp-proxy\n");
    if (c_packet->command != REPLY_TAPE_MTIO) {
	device_set_error(dself,
			 _("failed to get a REPLY_TAPE_MTIO from ndmp-proxy"),
			 DEVICE_STATUS_DEVICE_ERROR);
	return FALSE;
    }
    dbprintf("get REPLY_TAPE_MTIO %s packet from ndmp-proxy\n", cmd);
    error_str = c_packet->arguments[0].data;
    dbprintf("e %s\n", error_str);
    if (strcmp(error_str, "NDMP9_NO_ERR") != 0) {
	dbprintf("f %s\n", error_str);
	device_set_error(dself,
			 vstrallocf(_("REPLY_TAPE_MTIO %s: %s"), cmd, error_str),
			 DEVICE_STATUS_DEVICE_ERROR);
	dbprintf("g %s\n", error_str);
	return FALSE;
    }
    return TRUE;
}

static int
ndmp_device_robust_write(
    NdmpDevice  *nself,
    char        *buf,
    int          count,
    char       **errmsg)
{
    Device *dself = (Device*)nself;
    amprotocol_packet_t *c_packet;

    amprotocol_send_binary(nself->protocol, CMD_TAPE_WRITE, 1, count, buf);
    dbprintf("Sent CMD_TAPE_WRITE to ndmp-proxy\n");
    c_packet = amprotocol_get(nself->protocol);
    if (!c_packet) { exit(1); };
    if (c_packet->command != REPLY_TAPE_WRITE) { exit(1); };

    if (strcmp(c_packet->arguments[0].data, "NDMP9_NO_ERR") != 0) {
	*errmsg = stralloc(c_packet->arguments[0].data);
	device_set_error(dself,
		vstrallocf(_("Unknown error: %s"), c_packet->arguments[0].data),
		  DEVICE_STATUS_DEVICE_ERROR
		| DEVICE_STATUS_VOLUME_ERROR);
	free_amprotocol_packet(c_packet);
	return FALSE;
    }

    free_amprotocol_packet(c_packet);
    return TRUE;
}
