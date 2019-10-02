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
 * - try to figure out the right downstream branch automatically
 * - keep a tree of commits in order, so we can print out a sorted list
 *   of commits, from start to finish.  Otherwise, user needs to run output
 *   through order-commits.
 * - performance improvements
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <getopt.h>
#include <pthread.h>
#include <git2.h>
#include <errno.h>

#include "ccan/htable/htable.h"
#include "ccan/hash/hash.h"
#include "ccan/ciniparser/ciniparser.h"
#include "common.h"

#define CONFIG_FILE ".backportrc"

static regex_t backport_preg;
static regex_t cherrypick_preg;

static char *upstream_repo_dir, *downstream_repo_dir;
static char *downstream_branch = "refs/heads/master";
static char *start_commit;

#define SIZE_1G (1024 * 1024 * 1024)

/*
 * A hash table which keeps track of the commits from <start> to <end>
 * is kept for each of the upstream and downstream repos.  The number
 * of commits could be pretty large (10's of thousands), depending on
 * the specified start commit.
 */
#define HTABLE_DEFAULT_ENTRIES (128*1024)

void
usage(const char *prog)
{
	printf(
"%s -u <upstream repo path> -d <downstream repo path> -b <downstream branch>\n"
"\t-s <start commit> -o <output file>[path[, path] ...] ", prog);
}

void __attribute__ ((noreturn))
print_help(int rc)
{
	printf(
	  "Usage: %s <options> [path][,path]...\n"
	  "\n"
	  "Given two trees and an optional list of files, determine which commits\n"
	  "exist in tree A that don't exist in tree B.\n"
	  "\n"
	  "If the start-commit is backported to the downstream repository,\n"
	  "then the tool will automatically figure that out, and use the\n"
	  "correct downstream hash to start the history walk.\n"
	  "\n"
	  "Options:\n"
	  "  -u, --upstream-repo=<path>      path to upstream git repository;\n"
	  "  -d, --downstream-repo=<path>    path to downstream git repository;\n"
	  "  -b, --downstream-branch=<rev>   set downstream branch\n"
	  "                                  (default: %s);\n"
	  "  -s, --start-commit=<rev>        set the commit from which to start;\n"
	  "  -h, --help                      show this message and exit.\n"
	  "\n"
	  "Report bugs to authors.\n"
	  "\n",
	  program_invocation_short_name, downstream_branch);
	exit(rc);
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
free_cids(struct htable *ht)
{
	struct htable_iter i;
	char *hash;

	hash = htable_first(ht, &i);
	while (hash) {
		htable_delval(ht, &i);
		free(hash);
		hash = htable_next(ht, &i);
	}
}

static size_t
commit_rehash(const void *e, void __attribute__((unused)) *unused)
{
	return hash_string(e);
}

static bool
hash_cmp(const void *e, void *string)
{
	return(strcmp((char *)e, string) == 0);
}

void
add_commit_hash(struct htable *ht, const char *commit_hash)
{
	char *htable_ent = strdup(commit_hash);
	htable_add(ht, hash_string(htable_ent), htable_ent);
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
prune_list(struct htable *ht, const char *hash)
{
	char *match;
	size_t hashval = hash_string(hash);

	match = htable_get(ht, hashval, hash_cmp, hash);
	if (!match)
		return 0;
	htable_del(ht, hashval, match);
	free(match);
	return 1;
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
		{"help",	no_argument, NULL, 'h' },
		/* TODO: excludes file with list of commits we don't want */
	};

	while (1) {
		c = getopt_long(argc, argv, "u:d:b:s:o:h", long_options, NULL);
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
		case 'h':
			print_help(0);
			break;
		default:
			printf("Invalid argument '%c'\n", c);
			print_help(1);
			break;
		}
	}

	return optind;
}

git_diff_options diffopts = GIT_DIFF_OPTIONS_INIT;

bool
commit_modifies_paths(git_diff_options *diffopts, git_commit *commit)
{
	int i, ret, ret2;
	git_tree *commit_tree = NULL, *parent_tree = NULL;
	git_tree_entry *commit_ent, *parent_ent;
	git_commit *parent = NULL;
	bool modified = false;

	/* If no paths were specified, all commits are interesting. */
	if (diffopts->pathspec.count == 0)
		return true;

	if (git_commit_parent(&parent, commit, 0) < 0) {
		return false;
	}

	if (git_commit_tree(&commit_tree, commit) < 0) {
		liberror("git_commit_tree");
		git_commit_free(parent);
		return false;
	}

	if (git_commit_tree(&parent_tree, parent) < 0) {
		liberror("git_commit_tree");
		git_tree_free(commit_tree);
		git_commit_free(parent);
		return false;
	}

	for (i = 0; i < (int)diffopts->pathspec.count; i++) {
		ret = git_tree_entry_bypath(&parent_ent, parent_tree,
					    diffopts->pathspec.strings[i]);
		ret2 = git_tree_entry_bypath(&commit_ent, commit_tree,
					     diffopts->pathspec.strings[i]);
		/*
		 * If the path only exists in one revision, that means
		 * it was "changed".  If it doesn't exist in either
		 * revision, skip it.
		 */
		if (ret == GIT_ENOTFOUND && ret2 == GIT_ENOTFOUND)
			continue;
		/* path exists in only commit or parent */
		if (ret != ret2) {
			modified = true;
		} else {
			/* If the file changed, then the hash will change */
			if (!git_oid_equal(git_tree_entry_id(parent_ent),
					   git_tree_entry_id(commit_ent)))
				modified = true;
		}
		if (!ret)
			git_tree_entry_free(parent_ent);
		if (!ret2)
			git_tree_entry_free(commit_ent);
		if (modified)
			break;
	}

	git_tree_free(commit_tree);
	git_tree_free(parent_tree);
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
find_backported_commit(git_repository *downstream_repo, git_revwalk *walker,
		       const char *start_commit, int len, git_oid *out)
{
	int ret;
	int found = 0;
	git_oid oid;

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

	git_revwalk_reset(walker);
	return found;
}

typedef enum repo_type {
	REPO_TYPE_UPSTREAM = 0,
	REPO_TYPE_DOWNSTREAM,
} repo_type_t;

git_object *
revision_lookup(git_repository *repo, git_revwalk *walker,
		const char *spec, repo_type_t repo_type)
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
	if (find_backported_commit(repo, walker, spec, strlen(spec),
				   &backport_oid)) {
		ret = git_object_lookup(&revision, repo,
					&backport_oid, GIT_OBJ_COMMIT);
		if (ret < 0) {
			liberror("git_object_lookup");
			exit(1);
		}
	}

	return revision;
}

void
initialize_git_revwalk(git_revwalk *walker, git_object *start, const char *end)
{
	git_revwalk_reset(walker); // XXX
	if (git_revwalk_push_ref(walker, end) != 0) {
		liberror("git_revwalk_push");
		exit(1);
	}

	if (git_revwalk_hide(walker, git_object_id(start)) != 0) {
		liberror("git_revwalk_hide");
		exit(1);
	}

	git_revwalk_sorting(walker, GIT_SORT_TIME);
}

struct revwalk_args {
	git_repository *repo;
	repo_type_t type;
	const char *startrev;
	const char *endrev;
	struct htable ht;
};

void *
walk_history(void *p)
{
	struct revwalk_args *args = p;
	int ret;
	git_oid oid;
	git_repository *repo = args->repo;
	git_revwalk *walker;
	git_object *start;

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0) {
		liberror("git_revwalk_new");
		exit(1);
	}

	start = revision_lookup(repo, walker, args->startrev, args->type);
	if (!start) {
		fprintf(stderr, "Unable to find %s in %s repo.\n",
			start_commit, args->type == REPO_TYPE_UPSTREAM ?
			"upstream" : "downstream");
		exit(1);
	}

	initialize_git_revwalk(walker, start, args->endrev);

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
		if (git_commit_parentcount(commit) == 1 &&
		    commit_modifies_paths(&diffopts, commit)) {
			if (args->type == REPO_TYPE_UPSTREAM) {
				git_oid_tostr(hash, GIT_OID_HEXSZ + 1, &oid);
				add_commit_hash(&args->ht, hash);
			} else if (extract_backport(commit, hash) == 0) {
				add_commit_hash(&args->ht, hash);
			}
		}
		git_commit_free(commit);
	}

	git_revwalk_free(walker);
	return NULL;
}

int
main(int argc, char **argv)
{
	int ret, next_opt;
	git_repository *upstream_repo, *downstream_repo;
	pthread_t workers[2];
	struct revwalk_args upstream_args, downstream_args;
	int upstream_status, downstream_status;
	struct htable_iter i;
	char *hash;

	parse_config_file();
	init_regexes();

	next_opt = parse_options(argc, argv);
	if (next_opt < 0)
		exit(1);
	if (next_opt < argc) {
		diffopts.pathspec.strings = &argv[next_opt];
		diffopts.pathspec.count = argc - next_opt;
	}

	if (!upstream_repo_dir || !downstream_repo_dir || !start_commit) {
		print_help(1);
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

	upstream_args.repo = upstream_repo;
	upstream_args.type = REPO_TYPE_UPSTREAM;
	upstream_args.startrev = start_commit;
	upstream_args.endrev = "refs/heads/master";
	htable_init_sized(&upstream_args.ht, commit_rehash,
			  NULL, HTABLE_DEFAULT_ENTRIES);
	ret = pthread_create(&workers[0], NULL,
			     walk_history, (void *)&upstream_args);
	if (ret < 0) {
		perror("pthread_create");
		exit(1);
	}

	downstream_args.repo = downstream_repo;
	downstream_args.type = REPO_TYPE_DOWNSTREAM;
	downstream_args.startrev = start_commit;
	downstream_args.endrev = downstream_branch;
	htable_init_sized(&downstream_args.ht, commit_rehash,
			  NULL, HTABLE_DEFAULT_ENTRIES);
	ret = pthread_create(&workers[1], NULL,
			     walk_history, (void *)&downstream_args);

	pthread_join(workers[0], (void *)&upstream_status);
	pthread_join(workers[1], (void *)&downstream_status);

	git_repository_free(upstream_repo);
	git_repository_free(downstream_repo);

	git_libgit2_shutdown();

	hash = htable_first(&downstream_args.ht, &i);
	if (!hash)
		printf("Downstream hash table empty!\n");
	while (hash) {
		if (!prune_list(&upstream_args.ht, hash)) {
			printf("Unable to find commit %s in upstream list\n",
			       hash);
		}
		hash = htable_next(&downstream_args.ht, &i);
	}

	hash = htable_first(&upstream_args.ht, &i);
	while (hash) {
		printf("%s\n", hash);
		hash = htable_next(&upstream_args.ht, &i);
	}

	free_cids(&upstream_args.ht);
	free_cids(&downstream_args.ht);

	return 0;
}
/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  compile-command: "make"
 * End:
 */
