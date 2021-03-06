/*
 * Command line handling of vpddecode
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2005-2007 Jean Delvare <khali@linux-fr.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>

#include "include/dmiconfig.h"
#include "include/dmiutil.h"
#include "include/dmivpdopt.h"


/* Options are global */
struct opt opt;


/*
 * Handling of option --string
 */

/* This lookup table could admittedly be reworked for improved performance.
   Due to the low count of items in there at the moment, it did not seem
   worth the additional code complexity though. */
static const struct string_keyword opt_string_keyword[] = {
	{ "bios-build-id", 0x0D, 9 },
	{ "box-serial-number", 0x16, 7 },
	{ "motherboard-serial-number", 0x1D, 11 },
	{ "machine-type-model", 0x28, 7 },
	{ "bios-release-date", 0x30, 8 },
};

static void print_opt_string_list(void)
{
	unsigned int i;

	fprintf(stderr, "Valid string keywords are:\n");
	for (i = 0; i < ARRAY_SIZE(opt_string_keyword); i++)
	{
		fprintf(stderr, "  %s\n", opt_string_keyword[i].keyword);
	}
}

int 
parse_opt_string(const char *arg)
{
	unsigned int i;

	if (opt.string)
	{
		fprintf(stderr, "Only one string can be specified\n");
		return -1;
	}

	for (i = 0; i<ARRAY_SIZE(opt_string_keyword); i++)
	{
		if (!strcasecmp(arg, opt_string_keyword[i].keyword))
		{
			opt.string = &opt_string_keyword[i];
			return 0;
		}
	}

	fprintf(stderr, "Invalid string keyword: %s\n", arg);
	print_opt_string_list();
	return -1;
}


/*
 * Command line options handling
 */

/* Return -1 on error, 0 on success */
int parse_command_line(int argc, char * const argv[])
{
	int option;
	const char *optstring = "d:hs:uV";
	struct option longopts[] = {
		{ "dev-mem", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "string", required_argument, NULL, 's' },
		{ "dump", no_argument, NULL, 'u' },
		{ "version", no_argument, NULL, 'V' },
		{ 0, 0, 0, 0 }
	};

	while ((option = getopt_long(argc, argv, optstring, longopts, NULL)) != -1)
		switch (option)
		{
			case 'd':
				opt.devmem = optarg;
				break;
			case 's':
				if (parse_opt_string(optarg) < 0)
					return -1;
				opt.flags |= FLAG_QUIET;
				break;
			case 'u':
				opt.flags |= FLAG_DUMP;
				break;
			case 'V':
				opt.flags |= FLAG_VERSION;
				break;
			case '?':
				switch (optopt)
				{
					case 's':
						fprintf(stderr, "String keyword expected\n");
						print_opt_string_list();
						break;
				}
				return -1;
		}

	if ((opt.flags & FLAG_DUMP) && opt.string != NULL)
	{
		fprintf(stderr, "Options --string and --dump are mutually exclusive\n");
		return -1;
	}

	return 0;
}
