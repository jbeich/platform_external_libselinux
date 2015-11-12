/*
 * Binder Transaction Service contexts backend for labeling Android
 * Service Binder Transactions
 */

#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "callbacks.h"
#include "label_internal.h"

/* TODO: keep in sync with /platform/frameworks/native/include/binder/IBinder.h */
#define B_PACK_CHARS(c1, c2, c3, c4) \
    ((((c1)<<24)) | (((c2)<<16)) | (((c3)<<8)) | (c4))

/* A binder transaction security context specification */
struct spec {
    struct selabel_lookup_rec lr; /* holds contexts for lookup result */
    char *svc_name; /* binder interface name for binder service */
    int txn_code; /* txn code passed to onTransact */
};

#define SPECTAB_SIZE 256
//static struct 

/* All of the backend data necessary to make labeling decisions */
/*struct saved_data {

  };*/
/*
 * Backend interface routines
 */
static struct selabel_lookup_rec *lookup(struct selabel_handle *rec,
					 const char *key, int type)

{
	struct selabel_lookup_rec *ret = NULL;
    //    if (type == B_PACK_CHARS('_','D','M','P') && key != NULL)
	return ret;
}

static void closef(struct selabel_handle *rec)
{
    selinux_log(SELINUX_INFO, "Closing bdr_txn_handle\n");
}

static void stats(struct selabel_handle __attribute__((unused)) *rec)
{
	selinux_log(SELINUX_WARNING, "'stats' functionality not implemented.\n");
}

static bool partial_match(struct selabel_handle *h, const char *key) {
	selinux_log(SELINUX_WARNING, "'partial_match' functionality not implemented.\n");
    return false;
}

static struct selabel_lookup_rec *lookup_best_match(struct selabel_handle *rec,
        const char *key, const char **aliases, int type) {

	struct selabel_lookup_rec *ret = NULL;
	selinux_log(SELINUX_WARNING, "'lookup_best_match' functionality not (yet!) implemented.\n");
	return ret;
}

 static enum selabel_cmp_result cmp(struct selabel_handle *h1, struct selabel_handle *h2) {
	selinux_log(SELINUX_WARNING, "'cmp' functionality not implemented.\n");
    return SELABEL_INCOMPARABLE;
 }

int selabel_bdr_txn_init(struct selabel_handle *rec,
			  const struct selinux_opt *opts,
			  unsigned nopts)
{
	rec->data = NULL;
	rec->func_lookup = &lookup;
	rec->func_close = &closef;
	rec->func_stats = &stats;
	rec->func_partial_match = &partial_match;
	rec->func_lookup_best_match = &lookup_best_match;
    rec->func_cmp = &cmp;
	return 0;
}
