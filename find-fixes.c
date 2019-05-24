/*
 * find-fixes
 *
 * Description: Find commits which have a "Fixes:" tag for any of the commits
 * provided on the commandline.
 *
 * Author: Jeff Moyer <jmoyer@redhat.com>
 * Copyright(C) Red Hat, Inc., 2018
 *
 * TODO:
 * - implement output_file
 * - add a config file, at least to store the repo_dir
 * - better usage text: document defaults, etc
 * - factor out shared boilerplate between this and order-commits
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <regex.h>
#include <getopt.h>

#include "ccan/list/list.h"
#include "common.h"

static regex_t preg;

static char *repo_dir = ".";
static char *input_file;
static char *output_file;

void
usage(const char *prog)
{
	printf("%s [-r <repo path>] {-i <input cid file> | <cid> [cid] ...} "
	       "[-o <output file>\n", prog);
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

/*
 * Find any commit ids with a Fixes: tag matching those listed in cids.
 *
 * Return value: Number of commits with Fixes: tags pointing to @cids.
 */
int
find_fixes(git_repository *repo, git_revwalk *walker,
	   struct list_head *cids, struct list_head *result)
{
	int nr_found = 0;
	int ret;
	git_oid oid;
	git_commit *commit = NULL;
	struct cid *cid, *fix;
	const char *msg;

	/*
	 * Walk the history of the master branch, not whatever happens
	 * to be checked out right now.
	 */
	ret = git_revwalk_push_ref(walker, "refs/heads/master");
	if (ret < 0) {
		liberror("git_revwalk_push_ref");
		exit(1);
	}

	git_revwalk_sorting(walker, GIT_SORT_TIME);

	while (git_revwalk_next(&oid, walker) == 0) {
		LIST_HEAD(fixes);

		/*
		 * Check to see if we've passed a commit, and
		 * therefore no longer need to check for fixes for it.
		 * Do this first, as there's no use checking to see if
		 * this commit fixed something else on the list.
		 * After all, we've already included it.
		 */
		if (prune_list(cids, &oid)) {
			if (list_empty(cids))
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

		/*
		 * Check to see if the Fixes: tags contain commit hashes
		 * requested by the user.
		 */
		list_for_each(&fixes, fix, list) {
			list_for_each(cids, cid, list) {
				if (!memcmp(fix->hash, cid->hash,
					    GIT_OID_HEXSZ)) {
					char *hash = git_oid_tostr_s(&oid);
					ret = add_commit(repo, result, hash);
					if (ret)
						return -1;
					nr_found++;
					goto next;
				}
			}
		}
next:
		free_cids(&fixes);
		git_commit_free(commit);
	}

	return nr_found;
}

int
main(int argc, char **argv)
{
	int i, ret, next_opt;
	git_repository *repo;
	git_revwalk *walker;
	struct cid *cid;
	LIST_HEAD(cids);
	LIST_HEAD(result);

	next_opt = parse_options(argc, argv);
	if (next_opt < 0)
		exit(1);
	if (next_opt == argc && !input_file) {
		printf("No commit hashes specified.\n");
		usage(basename(argv[0]));
		exit(1);
	}

	/* regex for extracting Fixes tags from commit messages */
	regcomp(&preg, "^Fixes: ([0-9a-fA-F]+)", REG_EXTENDED|REG_NEWLINE);
	list_head_init(&cids);
	list_head_init(&result);

	git_libgit2_init();
	ret = git_repository_open(&repo, repo_dir);
	if (ret < 0) {
		liberror("git_repository_open");
		exit(1);
	}

	if (next_opt < argc) {
		/* any remaining arguments are commit hashes to check */
		for (i = next_opt; i < argc; i++) {
			if (add_commit(repo, &cids, argv[i]))
				exit(1);
		}
	}
	if (input_file) {
		ret = add_hashes_from_file(repo, input_file, &cids);
		if (ret)
			exit(1);
	}

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0) {
		liberror("git_revwalk_new");
		exit(1);
	}

	ret = find_fixes(repo, walker, &cids, &result);
	if (ret < 0)
		exit(1);

	/* print out the results */
	list_for_each(&result, cid, list)
		printf("%s\n", cid->hash);

	free_cids(&result);
	free_cids(&cids);

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
