/*
 * find-missing-commits
 *
 * Description: Given two trees and an optional list of files, determine
 * which commits exist in tree A that don't exist in tree B.
 *
 * Author: Jeff Moyer <jmoyer@redhat.com>
 * Copyright(C) Red Hat, Inc., 2019
 *
 *
 * Usage:
 *
 * find-missing-commits --upstream-repo <path> --downstream-repo <path>
 *                      --downstream-branch <git revision>
 *                      --start-commit <git revision>
 *                      [path][,path]...
 *
 * For example, to find the upstream commits missing from the RHEL 8.1 branch
 * in the fs/dax.c file:
 *
 * $ find-missing-commits --upstream-repo /sbox/src/kernel/upstream/linux \
 *                        --downstream-repo /sbox/src/kernel/kernel-rhel \
 *                        --downstream-branch rhel-8.1.0 \
 *                        --start-commit v4.18 \
 *                        fs/dax.c
 *
 * Note that the master branch is used for the upstream repository.
 *
 * If the start-commit is backported to the downstream repository,
 * then the tool will automatically figure that out, and use the
 * correct downstream hash to start the history walk.
 *
 * TODO:
 * - change from a list to a hash table
 * - better usage text: document defaults, etc
 * - try to figure out the right downstream branch
 * - keep a tree of commits in order, so we can print out a sorted list
 *   of commits, from start to finish.  Otherwise, user needs to run output
 *   through order-commits.
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
#include "ccan/ciniparser/ciniparser.h"
#include "common.h"

#define CONFIG_FILE ".backportrc"

static regex_t backport_preg;
static regex_t cherrypick_preg;

static char *upstream_repo_dir, *downstream_repo_dir;
static char *downstream_branch = "refs/heads/master";
static char *start_commit;
static char *output_file;

void
usage(const char *prog)
{
	printf(
"%s -u <upstream repo path> -d <downstream repo path> -b <downstream branch>\n"
"\t-s <start commit> -o <output file>[path[, path] ...] ", prog);
}

/*
 * config file name: ~/.backportrc
 *
 * ini-style config file.  Only one entry, currently:
 *
 * [repo]
 * path = /sbox/src/kernel/upstream/linux
 */
void
parse_config_file()
{
	dictionary *d;
	char *str;
	char config_file[FILENAME_MAX];
	char *homedir;

	homedir = getenv("HOME");
	if (!homedir) {
		perror("getenv");
		return;
	}
	snprintf(config_file, FILENAME_MAX, "%s/%s", homedir, CONFIG_FILE);

	d = ciniparser_load(config_file);
	if (!d)
		return;

	/*
	 * We want to destroy the dictionary once we're done parsing
	 * the ini file.  However, that will free the memory returned
	 * from ciniparser_getstring.  So, strdup the returned value.
	 */
	str = ciniparser_getstring(d, "repo:path", NULL);
	if (str) {
		upstream_repo_dir = strdup(str);
		if (!upstream_repo_dir) {
			perror("strdup");
			exit(1);
		}
	}

	ciniparser_freedict(d);
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
 * Given a RHEL commit message, find the upstream commit hash.
 *
 * Returns 0 if commit hash found, -1 on failure.
 */
int
extract_backport(git_commit *commit, char *result)
{
	int ret, match_len;
	regmatch_t pmatch[2]; /* single sub-expression */
	const char *p;

	p = git_commit_message(commit);

	ret = regexec(&backport_preg, p, 2, pmatch, 0);
	if (ret == 0) {
		match_len = pmatch[1].rm_eo - pmatch[1].rm_so;
		memcpy(result, p + pmatch[1].rm_so, match_len);
		result[match_len] = '\0';
		return 0;
	}

	ret = regexec(&cherrypick_preg, p, 2, pmatch, 0);
	if (ret == 0) {
		match_len = pmatch[1].rm_eo - pmatch[1].rm_so;
		memcpy(result, p + pmatch[1].rm_so, match_len);
		result[match_len] = '\0';

		return 0;
	}

	return -1;
}

/*
 * If hash is on list, then remove it.
 *
 * Returns 1 if hash matched a hash on the list.  0 if no match.
 */
int
prune_list(struct list_head *cids, const char *hash)
{
	struct cid *cid, *next;
	
	list_for_each_safe(cids, cid, next, list) {
		if (!strncmp(hash, cid->hash, GIT_OID_HEXSZ)) {
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
		{"upstream-repo",	required_argument, NULL, 'u' },
		{"downstream-repo",	required_argument, NULL, 'd' },
		{"downstream-branch",	required_argument, NULL, 'b' },
		{"start-commit",	required_argument, NULL, 's' },
		/* TODO: excludes file with list of commits we don't want */
	};

	while (1) {
		c = getopt_long(argc, argv, "u:d:b:s:o:", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
		case 'u':
			if (upstream_repo_dir)
				free(upstream_repo_dir);
			upstream_repo_dir = strdup(optarg);
			if (!upstream_repo_dir) {
				perror("strdup");
				return -1;
			}
			break;
		case 'd':
			if (downstream_repo_dir)
				free(downstream_repo_dir);
			downstream_repo_dir = strdup(optarg);
			if (!downstream_repo_dir) {
				perror("strdup");
				return -1;
			}
			break;
		case 'b':
			downstream_branch = malloc(strlen(optarg)
						   + strlen("refs/heads/") + 1);
			sprintf(downstream_branch, "refs/heads/%s", optarg);
			break;
		case 's':
			start_commit = strdup(optarg);
			if (!start_commit) {
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

/* if set, limits commit list to the specified paths */
static int path_match = 0;
git_diff_options diffopts = GIT_DIFF_OPTIONS_INIT;

bool
commit_modifies_paths(git_diff_options *diffopts,
		      git_commit *commit, git_repository *repo)
{
	git_tree *commit_tree = NULL, *parent_tree = NULL;
	git_commit *parent = NULL;
	unsigned num_parents;
	git_diff *diff = NULL;
	bool modified = false;

	/*
	 * If path matching isn't enabled, all commits are interesting.
	 */
	if (!path_match)
		return true;

	num_parents = git_commit_parentcount(commit);
	if (num_parents) {
		if (git_commit_parent(&parent, commit, 0) < 0) {
			liberror("git_commit_parent");
			return false;
		}
		if (git_commit_tree(&parent_tree, parent) < 0) {
			liberror("git_commit_tree");
			goto out_free_parent;
		}
	}

	if (git_commit_tree(&commit_tree, commit) < 0) {
		liberror("git_commit_tree");
		goto out_free_parent_tree;
	}

	/*
	 * If there are no parents for this commit, return true if the
	 * requested paths exist in the tree.  Otherwise, diff the two
	 * trees to see if there are any relevant changes.
	 */
	if (num_parents > 0) {
		if (git_diff_tree_to_tree(&diff, repo, parent_tree,
					  commit_tree, diffopts) < 0) {
			liberror("git_diff_tree_to_tree");
			goto out_free_commit_tree;
		}
		/*
		 * If ndeltas is non-zero, this commit touches paths that the
		 * user is interested in.
		 */
		modified = !!git_diff_num_deltas(diff);
		git_diff_free(diff);
	} else {
		git_pathspec *ps;

		if (git_pathspec_new(&ps, &diffopts->pathspec) < 0) {
			liberror("git_pathspec_new");
			goto out_free_commit_tree;
		}
		if (git_pathspec_match_tree(NULL, commit_tree,
					GIT_PATHSPEC_NO_MATCH_ERROR, ps) == 0)
			modified = true;
		git_pathspec_free(ps);
	}

out_free_commit_tree:
	git_tree_free(commit_tree);
out_free_parent_tree:
	if (num_parents)
		git_tree_free(parent_tree);
out_free_parent:
	if (num_parents)
		git_commit_free(parent);

	return modified;
}

/*
 * Two formats are supported for referencing upstream commit IDs.
 * 1) commit [0-9a-f]{40}
 * 2) (cherry picked from commit [0-9a-f]{40})
 * In the initial mail message, these expressions must be left
 * justified.
 */
void
init_regexes(void)
{
	regcomp(&backport_preg, "^commit ([0-9a-f]{40})",
		REG_EXTENDED|REG_NEWLINE);
	regcomp(&cherrypick_preg,
		"^[:space:]*\(cherry picked from commit ([0-9a-f]{40}))",
		REG_EXTENDED|REG_NEWLINE);
}

/*
 * Look for a backport of start_commit in the downstream_repo.  out
 * must be allocated by the caller.
 */
int
find_backported_commit(git_repository *downstream_repo, const char *start_commit,
		       int len, git_oid *out)
{
	int ret;
	int found = 0;
	git_revwalk *walker;
	git_oid oid;

	ret = git_revwalk_new(&walker, downstream_repo);
	if (ret < 0) {
		liberror("git_revwalk_new");
		exit(1);
	}
	ret = git_revwalk_push_ref(walker, downstream_branch);
	if (ret < 0) {
		liberror("git_revwalk_push_ref");
		exit(1);
	}
	git_revwalk_sorting(walker, GIT_SORT_TIME);

	while (git_revwalk_next(&oid, walker) == 0) {
		git_commit *commit;
		char upstream_hash[GIT_OID_HEXSZ + 1];

		ret = git_commit_lookup(&commit, downstream_repo, &oid);
		if (ret < 0) {
			liberror("git_commit_lookup");
			continue;
		}

		ret = extract_backport(commit, upstream_hash);
		git_commit_free(commit);
		if (ret < 0)
			continue;

		/* check to see if the commit matches start_commit */
		if (!memcmp(upstream_hash, start_commit, len)) {
			found = 1;
			git_oid_cpy(out, &oid);
			break;
		}
	}

	git_revwalk_free(walker);
	return found;
}

typedef enum repo_type {
	REPO_TYPE_UPSTREAM = 0,
	REPO_TYPE_DOWNSTREAM,
} repo_type_t;

git_object *
revision_lookup(git_repository *repo, const char *spec, repo_type_t repo_type)
{
	git_object *revision = 0;
	git_oid backport_oid;
	int ret;

	ret = git_revparse_single(&revision, repo, spec);
	if (ret == 0)
		return revision;

	/*
	 * We expect the commit to exist upstream, so fail if we
	 * didn't find it.
	 */
	if (repo_type == REPO_TYPE_UPSTREAM) {
		liberror("git_revparse");
		exit(1);
	}

	/*
	 * OK, this is a downstream repo.  Check to see if "spec" was
	 * backported.
	 */
	if (find_backported_commit(repo, spec, strlen(spec), &backport_oid)) {
		ret = git_object_lookup(&revision, repo,
					&backport_oid, GIT_OBJ_COMMIT);
		if (ret < 0) {
			liberror("git_object_lookup");
			exit(1);
		}
	}

	return revision;
}

git_revwalk *
initialize_git_revwalk(git_repository *repo, git_object *start, const char *end)
{
	git_revwalk *walker;
	int ret;

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0) {
		liberror("git_revwalk_new");
		exit(1);
	}

	if (git_revwalk_push_ref(walker, end) != 0) {
		liberror("git_revwalk_push");
		exit(1);
	}

	if (git_revwalk_hide(walker, git_object_id(start)) != 0) {
		liberror("git_revwalk_hide");
		exit(1);
	}

	git_revwalk_sorting(walker, GIT_SORT_TIME);
	if (ret < 0) {
		liberror("git_revwalk_hide_ref");
		exit(1);
	}

	return walker;
}

void
walk_history(git_revwalk *walker, git_repository *repo, repo_type_t type,
	     struct list_head *missing_commits)
{
	int ret;
	git_oid oid;

	while (git_revwalk_next(&oid, walker) == 0) {
		char hash[GIT_OID_HEXSZ + 1];
		git_commit *commit;

		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			liberror("git_commit_lookup");
			continue;
		}

		/*
		 * Restrict to the paths we're interested in, and skip
		 * merge commits.
		 */
		if (commit_modifies_paths(&diffopts, commit, repo) &&
		    git_commit_parentcount(commit) <= 1) {

			if (type == REPO_TYPE_UPSTREAM) {
				git_oid_tostr(hash, GIT_OID_HEXSZ + 1, &oid);
				__add_commit(missing_commits, hash);
			} else {
				if (extract_backport(commit, hash) == 0)
					prune_list(missing_commits, hash);
			}

		}
		git_commit_free(commit);
	}
}

int
main(int argc, char **argv)
{
	int ret, next_opt;
	git_repository *upstream_repo, *downstream_repo;
	git_revwalk *upstream_walker, *downstream_walker;
	git_object *upstream_start, *downstream_start;
	LIST_HEAD(missing_commits); /* present upstream, but not downstream */
	struct cid *cid;

	parse_config_file();
	init_regexes();

	next_opt = parse_options(argc, argv);
	if (next_opt < 0)
		exit(1);
	if (next_opt < argc) {
		diffopts.pathspec.strings = &argv[next_opt];
		diffopts.pathspec.count = argc - next_opt;
		path_match = 1;
	}

	if (!upstream_repo_dir || !downstream_repo_dir || !start_commit) {
		usage(basename(argv[0]));
		exit(1);
	}

	git_libgit2_init();
	ret = git_repository_open(&upstream_repo, upstream_repo_dir);
	if (ret < 0) {
		liberror("git_repository_open");
		exit(1);
	}

	ret = git_repository_open(&downstream_repo, downstream_repo_dir);
	if (ret < 0) {
		liberror("git_repository_open");
		exit(1);
	}

	upstream_start = revision_lookup(upstream_repo,
					 start_commit, REPO_TYPE_UPSTREAM);
	if (!upstream_start) {
		fprintf(stderr, "Unable to find %s in upstream repo.\n",
			start_commit);
		exit(1);
	}

	downstream_start = revision_lookup(downstream_repo,
					   start_commit, REPO_TYPE_DOWNSTREAM);
	if (!downstream_start) {
		fprintf(stderr, "Unable to find %s in downstream repo.\n",
			start_commit);
		exit(1);
	}	

	upstream_walker = initialize_git_revwalk(upstream_repo, upstream_start,
					"refs/heads/master");
	downstream_walker = initialize_git_revwalk(downstream_repo,
					downstream_start, downstream_branch);

	walk_history(upstream_walker, upstream_repo,
		     REPO_TYPE_UPSTREAM, &missing_commits);
	walk_history(downstream_walker, downstream_repo,
		     REPO_TYPE_DOWNSTREAM, &missing_commits);

	git_revwalk_free(upstream_walker);
	git_repository_free(upstream_repo);
	git_revwalk_free(downstream_walker);
	git_repository_free(downstream_repo);

	git_libgit2_shutdown();

	/* print out the missing commits */
	list_for_each(&missing_commits, cid, list) {
		printf("%s\n", cid->hash);
	}

	return 0;
}
/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  compile-command: "make"
 * End:
 */
