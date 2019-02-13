#include <git2.h>
#include "ccan/list/list.h"

struct cid {
	struct list_node	list;
	char			hash[GIT_OID_HEXSZ + 1];
};

/*
 * like perror, except prints out the gitlib error along with err.
 */
void liberror(const char *err);

/*
 * This function takes a (potentially) abbreviated hash, converts it to
 * an OID, and looks up the OID in the repo.  If the OID exists, the full
 * hash is extracted and returned to the caller.
 *
 * Returns 0 on success, with the resulting hash stored in out.  Returns
 * -1 on failure.
 */
int abbrev_to_full_hash(git_repository *repo, char *abbrev,
			int len, char *out);

/*
 * Validate the commit_hash and add to the list.
 *
 * Returns 0 on success, -1 on error.
 */
int add_commit(git_repository *repo, struct list_head *list,
	       char *commit_hash);

/*
 * Open filename and read in a list of commit hashes.  Validate the
 * commit hashes and add them to list.
 *
 * Returns 0 on success, -1 on error.
 */
int add_hashes_from_file(git_repository *repo, char *filename,
			 struct list_head *list);
