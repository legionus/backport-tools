/*
 * order-commits
 *
 * Copyright(C) 2018, Red Hat, Inc.
 *
 * author: Jeff Moyer <jmoyer@redhat.com>
 *
 * description: given a list of commit hashes, order them based on the
 *   git history order.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include "ccan/list/list.h"
#include "common.h"

struct cid {
	struct list_node	list;
	char			hash[GIT_OID_HEXSZ + 1];
};
LIST_HEAD(unordered);
LIST_HEAD(ordered);

void
usage(const char *prog)
{
	printf("%s <cid file> | <cid> [cid] ...\n", prog);
}

int
main(int argc, char **argv)
{
	int i, ret;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;
	struct cid *cid, *next;

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
			liberror("invalid hash");
			exit(1);
		}
		list_add(&unordered, &cid->list);
	}

	while (git_revwalk_next(&oid, walker) == 0) {

		list_for_each_safe(&unordered, cid, next, list) {
			if (git_oid_streq(&oid, cid->hash) == 0) {
				/*
				 * we are walking history in reverse order,
				 * so we add to the head of the ordered list.
				 */
				list_del(&cid->list);
				list_add(&ordered, &cid->list);
				break;
			}
		}

		if (list_empty(&unordered))
			break;
	}


	if (!list_empty(&unordered)) {
		printf("Unable to find the following commit(s) in the tree:\n");
		list_for_each_safe(&unordered, cid, next, list) {
			printf("%s\n", cid->hash);
			list_del(&cid->list);
			free(cid);
		}
	}

	if (!list_empty(&ordered)) {
		list_for_each_safe(&ordered, cid, next, list) {
			printf("%s\n", cid->hash);
			list_del(&cid->list);
			free(cid);
		}
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
