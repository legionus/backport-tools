/*
 * order-commits
 *
 * Copyright(C) 2018, 2019, Red Hat, Inc.
 *
 * Author: Jeff Moyer <jmoyer@redhat.com>
 *
 * Description: given a list of commit hashes, order them based on the
 *   git history order.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <getopt.h>

#include "ccan/list/list.h"
#include "common.h"

LIST_HEAD(unordered);
LIST_HEAD(ordered);

static char *repo_dir = ".";
static char *input_file;
static char *output_file;

void
usage(const char *prog)
{
	printf("%s [-r <repo path>] {-i <input cid file> | <cid> [cid] ...} "
	       "[-o <output file>\n", prog);
}

int
parse_options(int argc, char **argv)
{
	int c;
	static struct option long_options[] = {
		{"repo",	required_argument, NULL, 'r' },
		{"input-file",	required_argument, NULL, 'i' },
		{"output-file",	required_argument, NULL, 'o' },
	};

	while (1) {
		c = getopt_long(argc, argv, "r:i:o:", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
		case 'r':
			repo_dir = strdup(optarg);
			if (!repo_dir) {
				perror("strdup");
				return -1;
			}
			break;
		case 'i':
			input_file = strdup(optarg);
			if (!input_file) {
				perror("strdup");
				return -1;
			}
			break;
		case 'o':
			output_file = strdup(optarg);
			if (!output_file) {
				perror("strdup");
				return -1;
			}
			break;
		default:
			printf("Invalid argument '%c'\n", c);
			return -1;
		}
	}

	return optind;
}

int
main(int argc, char **argv)
{
	int i, ret, next_opt;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;
	struct cid *cid, *next;

	next_opt = parse_options(argc, argv);
	if (next_opt < 0)
		exit(1);
	if (next_opt == argc && !input_file) {
		printf("No commit hashes specified.\n");
		usage(basename(argv[0]));
		exit(1);
	}

	git_libgit2_init();

	ret = git_repository_open(&repo, repo_dir);
	if (ret < 0) {
		liberror("git_repository_open");
		exit(1);
	}

	if (next_opt < argc) {
		/* any remaining arguments are commit hashes to check */
		for (i = next_opt; i < argc; i++) {
			if (add_commit(repo, &unordered, argv[i]))
				exit(1);
		}
	}
	if (input_file) {
		ret = add_hashes_from_file(repo, input_file, &unordered);
		if (ret)
			exit(1);
	}

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0) {
		liberror("git_revwalk_new");
		exit(1);
	}
	/*
	 * Walk the history of the master branch, not whatever happens
	 * to be checked out right now.
	 */
	ret = git_revwalk_push_ref(walker, "refs/heads/master");
	if (ret < 0) {
		liberror("git_revwalk_push_ref");
		exit(1);
	}

	/*
	 * This mimics git-log output, and is necessary to get an
	 * accurate ordering of commits.  Beware, the documentation
	 * would lead you to believe otherwise.
	 */
	git_revwalk_sorting(walker, GIT_SORT_TIME);

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
