#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "regex.h"
#include "label_file.h"

int regex_prepare_data(struct regex_data ** regex, char const * pattern_string,
			struct regex_error_data * errordata) {
	memset(errordata, 0, sizeof(struct regex_error_data));
	*regex = regex_data_create();
	if (!(*regex))
		return -1;
#ifdef USE_PCRE2
	(*regex)->regex = pcre2_compile((PCRE2_SPTR)pattern_string,
			PCRE2_ZERO_TERMINATED,
			PCRE2_DOTALL,
			&errordata->error_code,
			&errordata->error_offset, NULL);
#else
	(*regex)->regex = pcre_compile(pattern_string, PCRE_DOTALL,
					&errordata->error_buffer,
					&errordata->error_offset, NULL);
#endif
	if (!(*regex)->regex) {
		goto err;
	}

#ifdef USE_PCRE2
	(*regex)->match_data =
		pcre2_match_data_create_from_pattern((*regex)->regex, NULL);
	if (!(*regex)->match_data) {
		goto err;
	}
#else
	(*regex)->sd = pcre_study((*regex)->regex, 0, &errordata->error_buffer);
	if (!(*regex)->sd && errordata->error_buffer) {
		goto err;
	}
	(*regex)->extra_owned = !!(*regex)->sd;
#endif
	return 0;

err:	regex_data_free(*regex);
	*regex = NULL;
	return -1;
}

const char *regex_version() {
#ifdef USE_PCRE2
	static int initialized = 0;
	static char * version_string = NULL;
	size_t version_string_len;
	if (!initialized) {
		version_string_len = pcre2_config(PCRE2_CONFIG_VERSION, NULL);
		version_string = (char*) malloc(version_string_len);
		if (!version_string) {
			return NULL;
		}
		pcre2_config(PCRE2_CONFIG_VERSION, version_string);
		initialized = 1;
	}
	return version_string;
#else
	return strdup(pcre_version());
#endif
}

int regex_load_mmap(struct mmap_area * mmap_area, struct regex_data ** regex) {
	int rc;
	size_t entry_len, info_len;

	rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
#ifdef USE_PCRE2
	if (rc < 0)
		return -1;

#ifndef NO_PERSISTENTLY_STORED_PATTERNS
	/* this should yield exactly one because we store one pattern at a time
	 */
	rc = pcre2_serialize_get_number_of_codes(mmap_area->next_addr);
	if (rc != 1)
		return -1;

	*regex = regex_data_create();
	if (!*regex)
		return -1;

	rc = pcre2_serialize_decode(&(*regex)->regex, 1,
			(PCRE2_SPTR)mmap_area->next_addr, NULL);
	if (rc != 1)
		goto err;

	(*regex)->match_data =
		pcre2_match_data_create_from_pattern((*regex)->regex, NULL);
	if (!(*regex)->match_data)
		goto err;

#endif /* NO_PERSISTENTLY_STORED_PATTERNS */
	/* and skip the decoded bit */
	rc = next_entry(NULL, mmap_area, entry_len);
	if (rc < 0)
		goto err;

	return 0;
#else
	if (rc < 0 || !entry_len) {
		rc = -1;
		return -1;
	}
	*regex = regex_data_create();
	if (!(*regex))
		return -1;

	(*regex)->regex = (pcre *) mmap_area->next_addr;
	rc = next_entry(NULL, mmap_area, entry_len);
	if (rc < 0)
		goto err;

	/* Check that regex lengths match. pcre_fullinfo()
	 * also validates its magic number. */
	rc = pcre_fullinfo((*regex)->regex, NULL, PCRE_INFO_SIZE, &info_len);
	if (rc < 0 || info_len != entry_len) {
		goto err;
	}

	rc = next_entry(&entry_len, mmap_area, sizeof(uint32_t));
	if (rc < 0 || !entry_len) {
		goto err;
	}
	(*regex)->lsd.study_data = (void *) mmap_area->next_addr;
	(*regex)->lsd.flags |= PCRE_EXTRA_STUDY_DATA;
	rc = next_entry(NULL, mmap_area, entry_len);
	if (rc < 0)
		goto err;

	/* Check that study data lengths match. */
	rc = pcre_fullinfo((*regex)->regex, &(*regex)->lsd,
	PCRE_INFO_STUDYSIZE,
				&info_len);
	if (rc < 0 || info_len != entry_len) {
		goto err;
	}
	(*regex)->extra_owned = 0;
	return 0;
#endif
	err: regex_data_free(*regex);
	*regex = NULL;
	return -1;
}

int regex_writef(struct regex_data * regex, FILE * fp) {
	int rc;
	size_t len;
#ifdef USE_PCRE2
	PCRE2_UCHAR * bytes;
	PCRE2_SIZE to_write;

#ifndef NO_PERSISTENTLY_STORED_PATTERNS
	/* encode the patter for serialization */
	rc = pcre2_serialize_encode(&regex->regex, 1, &bytes, &to_write, NULL);
	if (rc != 1)
		return -1;

#else
	to_write = 0;
#endif
	/* write serialized pattern's size */
	len = fwrite(&to_write, sizeof(uint32_t), 1, fp);
	if (len != 1) {
#ifndef NO_PERSISTENTLY_STORED_PATTERNS
		pcre2_serialize_free(bytes);
#endif
		return -1;
	}

#ifndef NO_PERSISTENTLY_STORED_PATTERNS
	/* write serialized pattern */
	len = fwrite(bytes, 1, to_write, fp);
	if (len != to_write) {
		pcre2_serialize_free(bytes);
		return -1;
	}
	pcre2_serialize_free(bytes);
#endif
#else
	uint32_t to_write;
	size_t size;
	pcre_extra * sd = regex->extra_owned ? regex->sd : &regex->lsd;

	/* determine the size of the pcre data in bytes */
	rc = pcre_fullinfo(regex->regex, NULL, PCRE_INFO_SIZE, &size);
	if (rc < 0)
		return -1;

	/* write the number of bytes in the pcre data */
	to_write = size;
	len = fwrite(&to_write, sizeof(uint32_t), 1, fp);
	if (len != 1)
		return -1;

	/* write the actual pcre data as a char array */
	len = fwrite(regex->regex, 1, to_write, fp);
	if (len != to_write)
		return -1;

	/* determine the size of the pcre study info */
	rc = pcre_fullinfo(regex->regex, sd, PCRE_INFO_STUDYSIZE, &size);
	if (rc < 0)
		return -1;

	/* write the number of bytes in the pcre study data */
	to_write = size;
	len = fwrite(&to_write, sizeof(uint32_t), 1, fp);
	if (len != 1)
		return -1;

	/* write the actual pcre study data as a char array */
	len = fwrite(sd->study_data, 1, to_write, fp);
	if (len != to_write)
		return -1;
#endif
	return 0;
}

struct regex_data * regex_data_create() {
	struct regex_data * dummy = (struct regex_data*) malloc(
			sizeof(struct regex_data));
	if (dummy) {
		memset(dummy, 0, sizeof(struct regex_data));
	}
	return dummy;
}

void regex_data_free(struct regex_data * regex) {
	if (regex) {
#ifdef USE_PCRE2
		if (regex->regex) {
			pcre2_code_free(regex->regex);
		}
		if (regex->match_data) {
			pcre2_match_data_free(regex->match_data);
		}
#else
		if (regex->regex)
			pcre_free(regex->regex);
		if (regex->extra_owned && regex->sd) {
			pcre_free_study(regex->sd);
		}
#endif
		free(regex);
	}
}

int regex_match(struct regex_data * regex, char const * subject, int partial) {
	int rc;
#ifdef USE_PCRE2
	rc = pcre2_match(regex->regex,
			(PCRE2_SPTR)subject, PCRE2_ZERO_TERMINATED, 0,
			partial ? PCRE2_PARTIAL_SOFT : 0, regex->match_data,
			NULL);
	if (rc > 0)
	return REGEX_MATCH;
	switch (rc) {
		case PCRE2_ERROR_PARTIAL:
			return REGEX_MATCH_PARTIAL;
		case PCRE2_ERROR_NOMATCH:
			return REGEX_NO_MATCH;
		default:
			return REGEX_ERROR;
	}
#else
	rc = pcre_exec(regex->regex,
			regex->extra_owned ? regex->sd : &regex->lsd, subject,
			strlen(subject), 0, partial ? PCRE_PARTIAL_SOFT : 0,
			NULL,
			0);
	switch (rc) {
		case 0:
			return REGEX_MATCH;
		case PCRE_ERROR_PARTIAL:
			return REGEX_MATCH_PARTIAL;
		case PCRE_ERROR_NOMATCH:
			return REGEX_NO_MATCH;
		default:
			return REGEX_ERROR;
	}
#endif
}

/* TODO Replace this compare function with something that actually compares the
 * regular expressions.
 * This compare function basically just compares the binary representations of
 * the automatons, and because this representation contains pointers and
 * metadata, it can only return a match if regex1 == regex2.
 * Preferably, this function would be replaced with an algorithm that computes
 * the equivalence of the automatons systematically.
 */
int regex_cmp(struct regex_data * regex1, struct regex_data * regex2) {
	int rc;
	size_t len1, len2;
#ifdef USE_PCRE2
	rc = pcre2_pattern_info(regex1->regex, PCRE2_INFO_SIZE, &len1);
	assert(rc == 0);
	rc = pcre2_pattern_info(regex2->regex, PCRE2_INFO_SIZE, &len2);
	assert(rc == 0);
	if (len1 != len2 || memcmp(regex1->regex, regex2->regex, len1))
		return SELABEL_INCOMPARABLE;
#else
	rc = pcre_fullinfo(regex1->regex, NULL, PCRE_INFO_SIZE, &len1);
	assert(rc == 0);
	rc = pcre_fullinfo(regex2->regex, NULL, PCRE_INFO_SIZE, &len2);
	assert(rc == 0);
	if (len1 != len2 || memcmp(regex1->regex, regex2->regex, len1))
		return SELABEL_INCOMPARABLE;
#endif
	return SELABEL_EQUAL;
}

void regex_format_error(struct regex_error_data const * error_data,
			char * buffer, size_t buf_size) {
	unsigned the_end_length = buf_size > 4 ? 4 : buf_size;
	char * ptr = &buffer[buf_size - the_end_length];
	int rc = 0;
	size_t pos = 0;
	if (!buffer || !buf_size)
		return;
	rc = snprintf(buffer, buf_size, "REGEX back-end error: ");
	if (rc < 0)
		/* If snprintf fails it constitutes a logical error that needs
		 * fixing.
		 */
		abort();

	pos += rc;
	if (pos >= buf_size)
		goto truncated;

	if (error_data->error_offset > 0) {
#ifdef USE_PCRE2
		rc = snprintf(buffer + pos, buf_size - pos, "At offset %lu: ",
				error_data->error_offset);
#else
		rc = snprintf(buffer + pos, buf_size - pos, "At offset %d: ",
				error_data->error_offset);
#endif
		if (rc < 0)
			abort();

	}
	pos += rc;
	if (pos >= buf_size)
		goto truncated;

#ifdef USE_PCRE2
	rc = pcre2_get_error_message(error_data->error_code,
			(PCRE2_UCHAR*)(buffer + pos),
			buf_size - pos);
	if (rc == PCRE2_ERROR_NOMEMORY)
		goto truncated;
#else
	rc = snprintf(buffer + pos, buf_size - pos, "%s",
			error_data->error_buffer);
	if (rc < 0)
		abort();

	if ((size_t)rc < strlen(error_data->error_buffer))
		goto truncated;
#endif

	return;

truncated:
	/* replace end of string with "..." to indicate that it was truncated */
	switch (the_end_length) {
		/* no break statements, fall-through is intended */
		case 4:
			*ptr++ = '.';
		case 3:
			*ptr++ = '.';
		case 2:
			*ptr++ = '.';
		case 1:
			*ptr++ = '\0';
		default:
			break;
	}
	return;
}
