/*
 * Unittest for Security Hash Locking Module
 *
 * Copyright 2020 Moxa Inc.
 *
 * Author: Chuck Lee <chucksc.lee@moxa.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "regex.h"
#include "tests/common/unittest_common.h"

struct regex_test_case {
    const char *condition;
    const char *dest;
    const char *src;
    int expected;
};

static const int STR_BUF_SIZE = 2048;

static struct regex_test_case regex_test_cases[] = {
    {
        .condition = "match full",
        .dest = "/var/log/run/disk",
        .src =  "/var/log/run/disk",
        .expected = 0,
    },
    {
        .condition = "match full, dest less",
        .dest = "/var/log/run/di",
        .src =  "/var/log/run/disk",
        .expected = 1,
    },
    {
        .condition = "match full, src less",
        .dest = "/var/log/run/disk",
        .src =  "/var/log/run/di",
        .expected = 1,
    },
    {
        .condition = "match end, dest less",
        .dest = "/var/log/run/*",
        .src =  "/var/log/run/disk",
        .expected = 0,
    },
    {
        .condition = "match end, dest more",
        .dest = "/var/log/run/disk/1/*",
        .src =  "/var/log/run/disk",
        .expected = 1,
    },
    {
        .condition = "match end, dest/src same",
        .dest = "/var/log/run/dis*",
        .src =  "/var/log/run/disk",
        .expected = 0,
    },
    {
        .condition = "match end, dest full",
        .dest = "/*",
        .src =  "/var/log/run/disk",
        .expected = 0,
    },
    {
        .condition = "match end, dest last char",
        .dest = "/var/log/run/disk/*",
        .src =  "/var/log/run/disk/",
        .expected = 1,
    },
    {
        .condition = "match middle, dest less",
        .dest = "/var/log/run/*/disk",
        .src =  "/var/log/run/12/disk",
        .expected = 0,
    },
    {
        .condition = "match middle, dest more",
        .dest = "/var/log/run/*/disk/1",
        .src =  "/var/log/run/12/disk",
        .expected = 1,
    },
    {
        .condition = "match middle, dest less",
        .dest = "/var/log/run/*/disk",
        .src =  "/var/log/run/12/disk/1",
        .expected = 1,
    },
    {
        .condition = "match middle, dest last char",
        .dest = "/var/log/run/disk*/",
        .src =  "/var/log/run/disk/",
        .expected = 1,
    },
    {
        .condition = "match middle, dest more",
        .dest = "/var/log/run/disk*/1",
        .src =  "/var/log/run/disk/",
        .expected = 1,
    },
    {
        .condition = "match end, dest last char diff",
        .dest = "/var/log/run/diskk",
        .src =  "/var/log/run/disk/",
        .expected = 1,
    },
};
static int regex_test_cases_size = \
    sizeof(regex_test_cases) / sizeof(struct regex_test_case);

static void _print_test_regex_result(struct regex_test_case *test_case,
                                     const int pass, const char *detail)
{
    if (!test_case || !detail) {
        return;
    }
    printf("Test %s: %s (%s)\n", pass ? "PASS" : "FAIL", test_case->condition,
           detail);
}

static enum test_status _test_regex(struct regex_test_case *test_cases,
                                    int test_cases_size,
                                    struct test_result *result) {
    if (!test_cases || !result) {
        return TEST_INVALID_ARG_NULL_POINTER;
    }

    result->total = test_cases_size;
    result->run = 0;
    result->pass = 0;

    char *dest = NULL;
    char *src = NULL;
    dest = malloc(sizeof(char) * STR_BUF_SIZE);
    src = malloc(sizeof(char) * STR_BUF_SIZE);

    if (!dest || !src) {
        free(dest);
        free(src);
        return TEST_MALLOC_FAIL;
    }

    for (int i = 0; i < test_cases_size; i++) {
        struct regex_test_case *test_case = &regex_test_cases[i];
        int pass = 0;

        result->run++;

        int dest_size = strlen(test_case->dest);
        if (dest_size >= STR_BUF_SIZE) {
            _print_test_regex_result(test_case, pass,
                                     "dest field of test case oversize");
            continue;
        }

        int src_size = strlen(test_case->src);
        if (src_size >= STR_BUF_SIZE) {
            _print_test_regex_result(test_case, pass,
                                     "src field of test case oversize");
            continue;
        }

        memset(dest, 0, sizeof(char) * STR_BUF_SIZE);
        memset(src, 0, sizeof(char) * STR_BUF_SIZE);

        strncpy(dest, test_case->dest, dest_size);
        strncpy(src, test_case->src, src_size);

        int compare_result = compare_regex(dest, src);
        pass = (compare_result == test_case->expected);

        if (pass) {
            result->pass++;
        }
        _print_test_regex_result(test_case, pass, pass ? "PASS" : "FAIL");
    }

    free(dest);
    free(src);

    return result->total == result->pass ? TEST_PASS : TEST_FAIL;
}

int main(void)
{
    struct test_result result;
    enum test_status status;

    status = _test_regex(regex_test_cases, regex_test_cases_size, &result);
    printf("%s (Total %d, Run %d, Pass %d)\n",
           status == TEST_PASS ? "PASS" : "FAIL",
           result.total,
           result.run,
           result.pass,
           test_status_str(status));

    return 0;
}
