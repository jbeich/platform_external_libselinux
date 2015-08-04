/*
 * This file contains helper functions for labeling support.
 *
 * Author : Richard Haines <richard_c_haines@btinternet.com>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include "label_internal.h"

/*
 * The read_spec_entries and read_spec_entry functions may be used to
 * replace sscanf to read entries from spec files. The file and
 * property services now use these.
 */

/* Read an entry from a spec file (e.g. file_contexts) */
static inline int read_spec_entry(char **entry, char **ptr, int *len)
{
	*entry = NULL;
	char *tmp_buf = NULL;

	while (isspace(**ptr) && **ptr != '\0')
		(*ptr)++;

	tmp_buf = *ptr;
	*len = 0;

	while (!isspace(**ptr) && **ptr != '\0') {
		(*ptr)++;
		(*len)++;
	}

	if (*len) {
		*entry = strndup(tmp_buf, *len);
		if (!*entry)
			return -1;
	}

	return 0;
}

/*
 * parse an m4 sync-line
 */
static void handle_syncline(struct m4_context *m4_ctx, char *buf_p) {

	char *p;
	char *saveptr;
	unsigned long lineno;
	m4_ctx->valid = 0;
	m4_ctx->lineno = 0;

	/* m4 -s sample: #line <no> "path/to/file" */
	p = buf_p;

	/* Ignore "#line" */
	p = strsep(&buf_p, " ");
	if (!p)
		return;

	/* returns: <no> */
	p = strsep(&buf_p, " ");
	if (!p)
		return;

	lineno = strtoul(p, &saveptr, 10);
	if (*saveptr != '\0')
		return;

	/* Sync lines are always >= 1 */
	lineno--;

	/* returns "path/to/file" */
	p = strsep(&buf_p, " \n");
	if (!p)
		return;

	/* trim quotes */
	p++;
	p[strlen(p) - 1] = '\0';

	m4_ctx->valid = 1;
	m4_ctx->lineno = lineno;
	strncpy(m4_ctx->path, p, M4_PATH_BUFFER_SIZE);
}

/*
 * m4_ctx   - Optional (NULL Ok) buffer to contain m4 context when encountering sync-lines
 * line_buf - Buffer containing the spec entries .
 * num_args - The number of spec parameter entries to process.
 * ...      - A 'char **spec_entry' for each parameter.
 * returns  - The number of items processed.
 *
 * This function calls read_spec_entry() to do the actual string processing.
 */
int hidden read_spec_entries(struct m4_context *m4_ctx, char *line_buf, int num_args, ...)
{
	char **spec_entry, *buf_p;
	int len, rc, items, entry_len = 0;
	va_list ap;

	len = strlen(line_buf);
	if (line_buf[len - 1] == '\n')
		line_buf[len - 1] = '\0';
	else
		/* Handle case if line not \n terminated by bumping
		 * the len for the check below (as the line is NUL
		 * terminated by getline(3)) */
		len++;

	buf_p = line_buf;
	while (isspace(*buf_p))
		buf_p++;

	/* attempt m4 sync-line */
	if (m4_ctx && !strncmp(buf_p, "#line", 5)) {
		handle_syncline(m4_ctx, buf_p);
		return 0;
	}

	/* Skip comment lines and empty lines. */
	if (*buf_p == '#'|| *buf_p == '\0') {
		return 0;
	}

	/* Process the spec file entries */
	va_start(ap, num_args);

	items = 0;
	while (items < num_args) {
		spec_entry = va_arg(ap, char **);

		if (len - 1 == buf_p - line_buf) {
			va_end(ap);
			return items;
		}

		rc = read_spec_entry(spec_entry, &buf_p, &entry_len);
		if (rc < 0) {
			va_end(ap);
			return rc;
		}
		if (entry_len)
			items++;
	}
	va_end(ap);
	return items;
}
