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

