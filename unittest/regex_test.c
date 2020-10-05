#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "regex_test.h"

int compare_regex(char *str1, int len1, char *str2, int len2)
{
	int i = 0;
	int asterik_offset = 0;
	int have_asterik = 0;
	int str1_leftover = 0;
	enum regex_match match = End;

	if ((len1 <= 0) || (len2 <= 0))
		return 1;

	// check * offset
	for(i=0; i<len1; i++) {
		asterik_offset = i;
		if(str1[i] == '*') {
			have_asterik = 1;
		       	break;
		}
	}

	if (have_asterik == 0)
		match = Full;
	else {
		// verify if * is in the middle of the str1
		if (asterik_offset == len1-1)
			match = End;
		else {
			match = Middle;
			str1_leftover = asterik_offset+1;
		}
	}

	;//printf( "Match is [%d], len %d, ", match, len1);

	if (match == Full) {
	       	;//printf( "str1 %s, compare %d bytes\n", str1, len1>len2?len1:len2);
		if (len1 > len2)
		       	return strncmp(str1, str2, len1) && 1;
		else
		       	return strncmp(str1, str2, len2) && 1;
	}
	else if (match == Middle) {
			int ret = 1;
			int ret1 = 1;
			char *p = NULL;

			ret = strncmp(str1, str2, asterik_offset) && 1;

			p = strstr(str2, str1+str1_leftover);
			if (p) {
				/**< find the leftover only if match last char */
				if (p[strlen(str1+str1_leftover)] == '\0') {
					ret1 = 0;
				}
			}

	       		return (ret || ret1);
	}
	else if (match == End) {
	       	;//printf( "str1 %s, compare %d bytes\n", str1, asterik_offset);
		if (strlen(str1) <= strlen(str2))
	       		return strncmp(str1, str2, asterik_offset) && 1;
	}
	else
	       	printf( "Unknown regular expression.\n");

	return 1;
}


int main(void)
{
	char *dest;
	char *src;
	dest = malloc(sizeof(char) * 2048);
	src = malloc(sizeof(char) * 2048);
	int dest_size = 0;
	int src_size = 0;

	/*************/
	printf("Testing match full\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/disk");
	strncpy(dest, "/var/log/run/disk", dest_size);

	src_size = strlen("/var/log/run/disk");
	strncpy(src, "/var/log/run/disk", src_size);

	printf("result: %d, expect 0\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match full, dest less\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/di");
	strncpy(dest, "/var/log/run/di", dest_size);

	src_size = strlen("/var/log/run/disk");
	strncpy(src, "/var/log/run/disk", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match full, src less\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/disk");
	strncpy(dest, "/var/log/run/disk", dest_size);

	src_size = strlen("/var/log/run/di");
	strncpy(src, "/var/log/run/di", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	/* src will never have asterik */
	printf("Testing match end, dest less\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/*");
	strncpy(dest, "/var/log/run/*", dest_size);

	src_size = strlen("/var/log/run/disk");
	strncpy(src, "/var/log/run/disk", src_size);

	printf("result: %d, expect 0\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match end, dest more\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/disk/1/*");
	strncpy(dest, "/var/log/run/disk/1/*", dest_size);

	src_size = strlen("/var/log/run/disk");
	strncpy(src, "/var/log/run/disk", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match end, dest/src same\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/dis*");
	strncpy(dest, "/var/log/run/dis*", dest_size);

	src_size = strlen("/var/log/run/disk");
	strncpy(src, "/var/log/run/disk", src_size);

	printf("result: %d, expect 0\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match end, dest full\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/*");
	strncpy(dest, "/*", dest_size);

	src_size = strlen("/var/log/run/disk");
	strncpy(src, "/var/log/run/disk", src_size);

	printf("result: %d, expect 0\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match end, dest last char\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/disk/*");
	strncpy(dest, "/var/log/run/disk/*", dest_size);

	src_size = strlen("/var/log/run/disk/");
	strncpy(src, "/var/log/run/disk/", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	/*************/
	/* src will never have asterik */
	printf("Testing match middle, dest less\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/*/disk");
	strncpy(dest, "/var/log/run/*/disk", dest_size);

	src_size = strlen("/var/log/run/12/disk");
	strncpy(src, "/var/log/run/12/disk", src_size);

	printf("result: %d, expect 0\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match middle, dest more\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/*/disk/1");
	strncpy(dest, "/var/log/run/*/disk/1", dest_size);

	src_size = strlen("/var/log/run/12/disk");
	strncpy(src, "/var/log/run/12/disk", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match middle, dest less\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/*/disk");
	strncpy(dest, "/var/log/run/*/disk", dest_size);

	src_size = strlen("/var/log/run/12/disk/1");
	strncpy(src, "/var/log/run/12/disk/1", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match middle, dest last char\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/disk*/");
	strncpy(dest, "/var/log/run/disk*/", dest_size);

	src_size = strlen("/var/log/run/disk/");
	strncpy(src, "/var/log/run/disk/", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	printf("Testing match middle, dest more\n");
	memset(dest, '\0', 2048); memset(src, '\0', 2048);
	dest_size = strlen("/var/log/run/disk*/1");
	strncpy(dest, "/var/log/run/disk*/1", dest_size);

	src_size = strlen("/var/log/run/disk/");
	strncpy(src, "/var/log/run/disk/", src_size);

	printf("result: %d, expect 1\n", compare_regex(dest, strlen(dest), src, strlen(src)));
	/*************/
	return 0;
}
