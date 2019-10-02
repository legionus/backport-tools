/*
 * find-fixes
 *
 * Description: Find commits which have a "Fixes:" tag for any of the commits
 * provided on the commandline.
 *
 * Author: Jeff Moyer <jmoyer@redhat.com>
 * Copyright(C) Red Hat, Inc., 2018, 2019
 *
 * TODO:
 * - better usage text: document defaults, etc
 * - factor out shared boilerplate between this and order-commits
 * - allow user to override default branch
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
#include "ccan/htable/htable.h"
#include "ccan/hash/hash.h"
#include "ccan/ciniparser/ciniparser.h"
#include "common.h"

#define CONFIG_FILE ".backportrc"

static regex_t preg;

static char *repo_dir;
static char *input_file;
static char *output_file;

void
usage(const char *prog)
{
	printf("%s [-r <repo path>] {-i <input cid file> | <cid> [cid] ...} "
	       "[-o <output file>\n", prog);
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
		repo_dir = strdup(str);
		if (!repo_dir) {
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
			if (repo_dir)
				free(repo_dir);
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

struct defective {
	struct list_head fixedby;
	char hash[GIT_OID_HEXSZ + 1];
};

static bool
defective_eq(const void *o, void *k)
{
	return(memcmp(((struct defective *) o)->hash, k, GIT_OID_HEXSZ) == 0);
}

static size_t
defective_hash(const void *o, void __attribute__((unused)) *unused)
{
	return hash_string(((struct defective *) o)->hash);
}

void
free_defective(struct htable *ht)
{
	void *p;
	struct htable_iter i;

	for (p = htable_first(ht, &i); p; p = htable_next(ht, &i)) {
		struct htable_iter i2;
		void *c;
		size_t h = ht->rehash(p, ht->priv);

		for (c = htable_firstval(ht, &i2, h);
		     c;
		     c = htable_nextval(ht, &i2, h)) {
			if (c == p) {
				free_cids(&((struct defective *) c)->fixedby);
				free(c);
				break;
			}
		}
	}
}

static int
in_list(struct list_head *cids, git_oid *oid)
{
	struct cid *cid;

	list_for_each(cids, cid, list) {
		if (git_oid_streq(oid, cid->hash) == 0)
			return 1;
	}
	return 0;
}

static void
append_commit(struct list_head *list, char *hash)
{
	struct cid *cid = malloc(sizeof(*cid));

	memcpy(cid->hash, hash, GIT_OID_HEXSZ);
	cid->hash[GIT_OID_HEXSZ] = '\0';
	list_add_tail(list, &cid->list);
}

static void
append_fix(struct htable *ht, char *hash, char *fix_hash)
{
	struct defective *commit = htable_get(ht, hash_string(hash),
			defective_eq, hash);

	if (!commit) {
		commit = malloc(sizeof(*commit));
		if (!commit) {
			perror("malloc");
			exit(1);
		}

		list_head_init(&commit->fixedby);

		memcpy(commit->hash, hash, GIT_OID_HEXSZ);
		commit->hash[GIT_OID_HEXSZ] = '\0';

		htable_add(ht, hash_string(commit->hash), commit);
	}

	append_commit(&commit->fixedby, fix_hash);
}

/*
 * Find any commit ids with a Fixes: tag matching those listed in cids.
 *
 * Return value: Number of @cids that were not found in tree.
 */
int
find_fixes(git_repository *repo, git_revwalk *walker,
           struct list_head *cids, struct htable *result)
{
	int nr_cids = 0;
	int ret;
	git_oid oid;
	git_commit *commit = NULL;
	struct cid *cid, *defective;
	const char *msg;

	list_for_each(cids, cid, list)
		nr_cids++;

	while (git_revwalk_next(&oid, walker) == 0) {
		LIST_HEAD(fixes);

		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			liberror("git_commit_lookup");
			continue;
		}

		msg = git_commit_message(commit);

		list_head_init(&fixes);
		extract_fixes_tags(repo, msg, &fixes);

		if (!list_empty(&fixes)) {
			char fix_hash[GIT_OID_HEXSZ + 1];
			git_oid_tostr(fix_hash, GIT_OID_HEXSZ + 1, &oid);

			list_for_each(&fixes, defective, list)
				append_fix(result, defective->hash, fix_hash);
		}

		free_cids(&fixes);
		git_commit_free(commit);

		if (in_list(cids, &oid)) {
			nr_cids--;
			if (!nr_cids) {
				break;
			}
		}
	}

	git_revwalk_reset(walker);
	return nr_cids;
}

int
main(int argc, char **argv)
{
	int i, ret, next_opt;
	git_repository *repo;
	git_revwalk *walker;
	LIST_HEAD(cids);
	struct cid *cid;
	size_t nr_cids = 0;
	struct htable tagged;
	FILE *stream = stdout;
	char *range = NULL;

	parse_config_file();

	next_opt = parse_options(argc, argv);
	if (next_opt < 0)
		exit(1);
	if (next_opt == argc && !input_file) {
		printf("No commit hashes specified.\n");
		usage(basename(argv[0]));
		exit(1);
	}

	/*
	 * Set repo_dir to PWD if it was not specified in the config
	 * file or on the command line.
	 */
	if (!repo_dir)
		repo_dir = ".";

	/* regex for extracting Fixes tags from commit messages */
	regcomp(&preg, "^Fixes: ([0-9a-fA-F]+)", REG_EXTENDED|REG_NEWLINE);
	list_head_init(&cids);
	htable_init(&tagged, defective_hash, NULL);

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

	if (output_file) {
		stream = fopen(output_file, "w+");
		if (!stream) {
			perror("fopen");
			stream = stdout;
		}
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

	list_for_each(&cids, cid, list)
		nr_cids++;

	if (nr_cids > 1) {
		git_oid base;
		char *oids = calloc(nr_cids, sizeof(git_oid));

		i = 0;
		list_for_each(&cids, cid, list) {
			if (git_oid_fromstrp(
				    (git_oid *)(oids + (i * sizeof(git_oid))),
				    cid->hash) != 0) {
				fprintf(stderr, "Unable to parse OID: %s\n",
					cid->hash);
				exit(1);
			}
			i++;
		}

		ret = git_merge_base_octopus(&base, repo, nr_cids, (git_oid *)oids);
		if (!ret) {
			if (asprintf(&range, "%s^..",
				     git_oid_tostr_s(&base)) < 0) {
				perror("asprintf");
				exit(1);
			}
		} else if (ret < 0 && ret != GIT_ENOTFOUND) {
			liberror("git_merge_base_many");
			exit(1);
		}

	} else if (nr_cids == 1) {
		char *range;

		cid = list_top(&cids, struct cid, list);
		if (!cid) {
			fprintf(stderr, "Unable to get first cid from list!\n");
			exit(1);
		}

		if (asprintf(&range, "%s^..", cid->hash) < 0) {
			perror("asprintf");
			exit(1);
		}

	} else {
		fprintf(stderr, "Nothing to do.\n");
		exit(1);
	}

	if (range) {
		ret = git_revwalk_push_range(walker, range);
		if (ret < 0) {
			liberror("git_revwalk_push_range");
			exit(1);
		}
		free(range);
	}

	git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL);

	ret = find_fixes(repo, walker, &cids, &tagged);
	if (ret != 0) {
		fprintf(stderr, "find_fixes: unable to find one or more of the "
			"specified commits in the upstream repo.");
		exit(1);
	}

	do {
		struct cid *fix, *next;

		list_for_each_safe(&cids, cid, next, list) {
			struct defective *commit = htable_get(&tagged,
					hash_string(cid->hash), defective_eq,
					cid->hash);

			list_del(&cid->list);
			free(cid);

			/* no one fixes this commit. */
			if (!commit)
				continue;

			/* print out the results */
			list_for_each(&commit->fixedby, fix, list)
				fprintf(stream, "%s\n", fix->hash);

			/*
			 * Move the "Fixes:" commits into the cids list, and
			 * re-run the walk.  This will find the fixes for the
			 * fixes (for the fixes (for the fixes....))
			 */
			list_append_list(&cids, &commit->fixedby);
		}
	} while (!list_empty(&cids));

	free_cids(&cids);
	free_defective(&tagged);
	htable_clear(&tagged);
	regfree(&preg);

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
