/*
 * order-commits - given a list of commit hashes, order them based on
 *                 the git history order.
 *
 * Copyright(C) 2018, 2019, Red Hat, Inc.
 * Author: Jeff Moyer <jmoyer@redhat.com>
 * License: GPLv2
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "ccan/list/list.h"
#include "common.h"

LIST_HEAD(unordered);
LIST_HEAD(ordered);

static char *repo_dir = ".";
static char *input_file;
static char *output_file;

void __attribute__ ((noreturn))
print_help(int rc)
{
	printf(
	  "Usage: %1$s [OPTIONS] <cid> [cid] ...\n"
	  "   or: %1$s [OPTIONS] -i <file>\n"
	  "\n"
	  "This utility is used to order commits based on the git history order.\n"
	  "\n"
	  "Options:\n"
	  "  -r, --repo=<repo>          use the specified repository for search;\n"
	  "  -i, --input-file=<file>    read the commits from the specified file;\n"
	  "  -o, --output-file=<file>   write the found commit to the file;\n"
	  "  -h, --help                 show this message and exit.\n"
	  "\n"
	  "Report bugs to authors.\n"
	  "\n",
	  program_invocation_short_name);
	exit(rc);
}

int
parse_options(int argc, char **argv)
{
	int c;
	static struct option long_options[] = {
		{"repo",	required_argument, NULL, 'r' },
		{"input-file",	required_argument, NULL, 'i' },
		{"output-file",	required_argument, NULL, 'o' },
		{"help",	no_argument, NULL, 'h' },
	};

	while (1) {
		c = getopt_long(argc, argv, "r:i:o:h", long_options, NULL);
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

int
main(int argc, char **argv)
{
	int i, ret, next_opt;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;
	FILE *stream = stdout;
	struct cid *cid, *next;

	next_opt = parse_options(argc, argv);
	if (next_opt < 0)
		exit(1);
	if (next_opt == argc && !input_file) {
		printf("No commit hashes specified.\n");
		print_help(1);
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
		fprintf(stderr, "Unable to find the following commit(s) in the tree:\n");
		list_for_each_safe(&unordered, cid, next, list) {
			fprintf(stderr, "%s\n", cid->hash);
			list_del(&cid->list);
			free(cid);
		}
		fprintf(stderr, "\n");
	}

	if (output_file) {
		stream = fopen(output_file, "w+");
		if (!stream) {
			perror("fopen");
			stream = stdout;
		}
	}

	if (!list_empty(&ordered)) {
		list_for_each_safe(&ordered, cid, next, list) {
			fprintf(stream, "%s\n", cid->hash);
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
