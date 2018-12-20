/*
 * find-fixes
 *
 * Description: Find commits which have a "Fixes:" tag for any of the commits
 * provided on the commandline.
 *
 * Author: Jeff Moyer <jmoyer@redhat.com>
 * Copyright(C) Red Hat, Inc., 2018
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <regex.h>

#include "ccan/list/list.h"
#include "common.h"

struct cid {
	struct list_node	list;
	char			hash[GIT_OID_HEXSZ + 1];
};
LIST_HEAD(cids);
static regex_t preg;

void
usage(const char *prog)
{
	printf("%s <cid file> | <cid> [cid] ...\n", prog);
}

void
free_cids(struct list_head *head)
{
	struct cid *cid, *next;

	list_for_each_safe(head, cid, next, list) {
		list_del(&cid->list);
		free(cid);
	}
}

/*
 * Given a commit message, return a list of hashes that this
 * commit Fixes:.  The list_head should be initialized prior to
 * calling this function.
 */
void
extract_fixes_tags(git_repository *repo,
		   const char *msg, struct list_head *result)
{
	int ret, match_len;
	regmatch_t pmatch[2]; /* single sub-expression */
	char match[GIT_OID_HEXSZ + 1];
	const char *p = msg;
	struct cid *cid;

	while (1) {
		ret = regexec(&preg, p, 2, pmatch, 0);
		if (ret != 0)
			return;

		match_len = pmatch[1].rm_eo - pmatch[1].rm_so;
		memcpy(match, p + pmatch[1].rm_so, match_len);
		match[match_len] = '\0';

		cid = malloc(sizeof(*cid));
		ret = abbrev_to_full_hash(repo, match, match_len, cid->hash);
		if (ret == 0)
			list_add(result, &cid->list);
		else
			free(cid);
		/* continue the search after the match */
		p += pmatch[1].rm_eo;
	}
}

/*
 * If oid is on list, then remove it.
 *
 * Returns 1 if oid matched a hash on the list.  0 if no match.
 */
int
prune_list(struct list_head *cids, git_oid *oid)
{
	struct cid *cid, *next;
	
	list_for_each_safe(cids, cid, next, list) {
		if (git_oid_streq(oid, cid->hash) == 0) {
			list_del(&cid->list);
			free(cid);
			return 1;
		}
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int i, ret;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;
	git_commit *commit = NULL;
	struct cid *cid, *fix;
	const char *msg;

	if (argc < 2) {
		usage(basename(argv[0]));
		exit(1);
	}

	git_libgit2_init();

	ret = git_repository_open(&repo, ".");
	if (ret < 0) {
		liberror("git_repository_open");
		exit(1);
	}
	ret = git_revwalk_new(&walker, repo);
	if (ret < 0) {
		liberror("git_revwalk_new");
		exit(1);
	}
	ret = git_revwalk_push_head(walker);
	if (ret < 0) {
		liberror("git_revwalk_push_head");
		exit(1);
	}

	regcomp(&preg, "^Fixes: ([0-9a-fA-F]+)", REG_EXTENDED|REG_NEWLINE);

	/*
	 * Look up the commit hashes to make sure they exist and are
	 * unique.
	 */
	for (i = 1; i < argc; i++) {

		if (strlen(argv[i]) > GIT_OID_HEXSZ) {
			fprintf(stderr, "Invalid commit hash: \"%s\"\n",
				argv[i]);
			exit(1);
		}

		cid = malloc(sizeof(*cid));
		ret = abbrev_to_full_hash(repo, argv[i],
					  strlen(argv[i]), cid->hash);
		if (ret < 0) {
			liberror("invalid hash\n");
			exit(1);
		}
		list_add(&cids, &cid->list);
	}

	while (git_revwalk_next(&oid, walker) == 0) {
		LIST_HEAD(fixes);

		/*
		 * Check to see if we've passed a commit, and
		 * therefore no longer need to check for fixes for it.
		 * Do this first, as there's no use checking to see if
		 * this commit fixed something else on the list.
		 * After all, we've already included it.
		 */
		if (prune_list(&cids, &oid)) {
			if (list_empty(&cids))
				break;
			continue;
		}

		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			liberror("git_commit_lookup");
			continue;
		}

		msg = git_commit_message(commit);

		list_head_init(&fixes);
		extract_fixes_tags(repo, msg, &fixes);

		list_for_each(&fixes, fix, list) {
			list_for_each(&cids, cid, list) {
				if (!memcmp(fix->hash, cid->hash,
					    GIT_OID_HEXSZ)) {
					printf("%s\n", git_oid_tostr_s(&oid));
					goto next;
				}
			}
		}
next:
		free_cids(&fixes);
		git_commit_free(commit);
	}

	git_revwalk_free(walker);
	git_repository_free(repo);
	git_libgit2_shutdown();

	return 0;
}
/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  compile-command: "make"
 * End:
 */
