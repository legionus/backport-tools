#include <stdio.h>
#include <string.h>
#include "common.h"

void
liberror(const char *err)
{
	fprintf(stderr, "%s: %s\n", err, giterr_last()->message);
}

/*
 * this function takes a (potentially) abbreviated hash, converts it to
 * an OID, and looks up the OID in the repo.  If the OID exists, the full
 * hash is extracted and returned to the caller.
 *
 * returns 0 on success, with the resulting hash stored in out.
 */
int
abbrev_to_full_hash(git_repository *repo, char *abbrev, int len, char *out)
{
	int ret;
	git_oid oid;
	git_commit *commit = NULL;

	ret = git_oid_fromstrn(&oid, abbrev, len);
	if (ret != 0)
		return -1;

	ret = git_commit_lookup_prefix(&commit, repo, &oid, len);
	if (ret < 0)
		return -1;

	git_oid_tostr(out, GIT_OID_HEXSZ + 1, git_commit_id(commit));
	out[GIT_OID_HEXSZ] = '\0';
	git_commit_free(commit);

	if (strlen(out) == 0)
		return -1;

	return 0;
}

/*
 * Look up the commit hashes to make sure they exist and are unique.
 */
int
add_commit(git_repository *repo, struct list_head *list, char *commit_hash)
{
	int ret;
	int len = strlen(commit_hash);
	struct cid *cid;

	if (len > GIT_OID_HEXSZ) {
		fprintf(stderr, "Invalid commit hash: \"%s\"\n", commit_hash);
		return -1;
	}

	cid = malloc(sizeof(*cid));
	ret = abbrev_to_full_hash(repo, commit_hash, len, cid->hash);
	if (ret < 0) {
		liberror("invalid hash");
		printf("\"%s\"\n", commit_hash);
		return -1;
	}
	list_add(list, &cid->list);
	return 0;
}

int
add_hashes_from_file(git_repository *repo, char *filename,
		     struct list_head *list)
{
	FILE *fp;
	int ret;
	char line[GIT_OID_HEXSZ + 1];

	fp = fopen(filename, "r");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	while (fgets(line, GIT_OID_HEXSZ + 1, fp) != NULL) {
		int len = strlen(line);
		if (line[len-1] == '\n')
			line[len-1] = '\0';
		/* check for empty line */
		if (strlen(line) == 0)
			continue;
		ret = add_commit(repo, list, line);
		if (ret) {
			fclose(fp);
			return ret;
		}
	}
	if (ferror(fp)) {
		perror("fgets");
		return -1;
	}
	fclose(fp);
	return 0;
}
