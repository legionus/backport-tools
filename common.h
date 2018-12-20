#include <git2.h>

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
int abbrev_to_full_hash(git_repository *repo, char *abbrev, int len, char *out);

