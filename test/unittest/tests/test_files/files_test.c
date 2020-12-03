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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "linux/seq_file.h"
#include "files.h"
#include "notify.h"
#include "tests/common/unittest_common.h"
#include "mocks/linux/mm/mock_slab.h"

int locking;
int hb_level;
int hb_interact;
unsigned long total_notify_record;
hb_notify_ll hb_notify_list_head;
extern hb_file_ll hb_file_list_head;

struct test_file_record {
    unsigned int fid;
    const char *uid;
    char act_allow;
    const char *filename;
    const char *binprm;
    unsigned int cmd;
    unsigned long arg;
};

struct files_search_test_case {
    const char *condition;
    int hb_level;
    unsigned int fid;
    uid_t uid;
    const char *filename;
    const char *binprm;
    unsigned int cmd;
    unsigned long arg;
    int expected;
};

#define STR_BUF_SIZE (2048)

static struct test_file_record test_file_records[] = {
    {
        .fid = HB_FILE_IOCTL,
        .uid = "*",
        .act_allow = 'A',
        .filename = "/a/b/c",
        .binprm = "/z/y/x",
        .cmd = 1,
        .arg = 1,
    },
    {
        .fid = HB_FILE_OPEN,
        .uid = "1000",
        .act_allow = 'R',
        .filename = "/a/b/d",
        .binprm = "/z/y/w",
        .cmd = 1,
        .arg = 2,
    },
};
static int test_file_records_size = \
    sizeof(test_file_records) / sizeof(struct test_file_record);

static struct files_search_test_case files_search_test_cases[] = {
    {
        .condition = "uid 0 match *, filename(no-regex), cmd, and arg match",
        .hb_level = 1,
        .fid = HB_FILE_IOCTL,
        .uid = 0,
        .filename = "/a/b/c",
        .binprm = "/z/y/x",
        .cmd = 1,
        .arg = 1,
        .expected = 1,
    },
    {
        .condition = "uid 100 match *, filename(no-regex) and cmd match, ignore arg",
        .hb_level = 1,
        .fid = HB_FILE_IOCTL,
        .uid = 100,
        .filename = "/a/b/c",
        .binprm = "/z/y/x",
        .cmd = 1,
        .arg = 2,
        .expected = 1,
    },
    {
        .condition = "uid 0 match *, filename(no-regex), cmd and arg match",
        .hb_level = 2,
        .fid = HB_FILE_IOCTL,
        .uid = 0,
        .filename = "/a/b/c",
        .binprm = "/z/y/x",
        .cmd = 1,
        .arg = 1,
        .expected = 1,
    },
    {
        .condition = "uid 100 match *, filename(no-regex), cmd and arg match",
        .hb_level = 2,
        .fid = HB_FILE_IOCTL,
        .uid = 100,
        .filename = "/a/b/c",
        .binprm = "/z/y/x",
        .cmd = 1,
        .arg = 1,
        .expected = 1,
    },
    {
        .condition = "uid 100 match *, filename(no-regex) and cmd match, arg mismatch",
        .hb_level = 2,
        .fid = HB_FILE_IOCTL,
        .uid = 100,
        .filename = "/a/b/c",
        .binprm = "/z/y/x",
        .cmd = 1,
        .arg = 2,
        .expected = 0,
    },
    {
        .condition = "uid 1000 match 1000, filename(no-regex) and cmd match",
        .hb_level = 1,
        .fid = HB_FILE_OPEN,
        .uid = 1000,
        .filename = "/a/b/d",
        .binprm = "/z/y/w",
        .cmd = 1,
        .arg = 2,
        .expected = 1,
    },
    {
        .condition = "uid 1000 match 1000, filename(no-regex) and cmd match, ignore arg",
        .hb_level = 1,
        .fid = HB_FILE_OPEN,
        .uid = 1000,
        .filename = "/a/b/d",
        .binprm = "/z/y/w",
        .cmd = 1,
        .arg = 1,
        .expected = 1,
    },
    {
        .condition = "uid 0 mismatch 1000",
        .hb_level = 1,
        .fid = HB_FILE_OPEN,
        .uid = 0,
        .filename = "/a/b/d",
        .binprm = "/z/y/w",
        .cmd = 1,
        .arg = 2,
        .expected = 0,
    },
};
static int files_search_test_cases_size = \
    sizeof(files_search_test_cases) / sizeof(struct files_search_test_case);

static int _create_test_file_record(void)
{
    INIT_LIST_HEAD(&hb_file_list_head.list);
    for (int i = 0; i < test_file_records_size; i++) {
        struct test_file_record *file_record = &test_file_records[i];
        char uid[UID_STR_SIZE];
        char filename[PATH_MAX];
        char binprm[PATH_MAX];

        snprintf(uid, UID_STR_SIZE, file_record->uid);
        snprintf(filename, PATH_MAX, file_record->filename);
        snprintf(binprm, PATH_MAX, file_record->binprm);

        int result = add_file_record(file_record->fid, uid,
                                     file_record->act_allow, filename, binprm,
                                     file_record->cmd, file_record->arg);

        if (result != 0) {
            return -1;
        }
    }

    return 0;
}

static int _release_test_file_record(void)
{
    hb_file_ll *tmp = NULL;
    struct list_head *pos = NULL;
    struct list_head *q = NULL;

    list_for_each_safe(pos, q, &hb_file_list_head.list) {
        tmp = list_entry(pos, hb_file_ll, list);
        list_del(pos);
        free_file_record(tmp);
        free(tmp);
        tmp = NULL;
    }
}

static void _print_files_search_test_result(
        struct files_search_test_case *test_case,
        const int pass,
        const char *detail)
{
    if (!test_case || !detail) {
        return;
    }
    printf("Test %s: %s (%s)\n", pass ? "PASS" : "FAIL", test_case->condition,
           detail);
}

static enum test_status _test_search_file_record(
        struct files_search_test_case *test_cases,
        int test_cases_size,
        struct test_result *result)
{
    if (!test_cases || !result) {
        return TEST_INVALID_ARG_NULL_POINTER;
    }

    result->total = test_cases_size;
    result->run = 0;
    result->pass = 0;

    if (_create_test_file_record() != 0) {
        _release_test_file_record();
        return TEST_SETUP_FAIL;
    }
 
    for (int i = 0; i < test_cases_size; i++) {
        struct files_search_test_case *test_case = &test_cases[i];
        char filename[PATH_MAX] = {0};
        char binprm[PATH_MAX] = {0};
        int pass = 0;

        result->run++;

        if (strlen(test_case->filename) >= PATH_MAX) {
            _print_files_search_test_result(
                test_case, pass, "filename field of test case oversize");
            continue;
        }
        if (strlen(test_case->binprm) >= PATH_MAX) {
            _print_files_search_test_result(
                test_case, pass, "binprm field of test case oversize");
            continue;
        }

        snprintf(filename, PATH_MAX, test_case->filename);
        snprintf(binprm, PATH_MAX, test_case->binprm);
        hb_level = test_case->hb_level;

        start_kmalloc_detect();

        hb_file_ll *search_result = search_file_record(test_case->fid,
                                                       test_case->uid,
                                                       filename,
                                                       binprm,
                                                       test_case->cmd,
                                                       test_case->arg);
        stop_kmalloc_detect();

        int kmalloc_count = get_kmalloc_count();
        char msg[STR_BUF_SIZE] = {0};
        if (kmalloc_count > 0) {
            snprintf(msg, STR_BUF_SIZE, "%d memory leaks caused by kmalloc()",
                     kmalloc_count);
            _print_files_search_test_result(test_case, pass, msg);
            continue;
        } else if (kmalloc_count < 0) {
            snprintf(msg, STR_BUF_SIZE, "%d double memory free caused by kfree()"
                     -kmalloc_count);
            _print_files_search_test_result(test_case, pass, msg);
            continue;
        }

        if ((search_result && test_case->expected)
            || (!search_result && !test_case->expected)) {
            pass = 1;
        }

        if (pass) {
            result->pass++;
        }
        _print_files_search_test_result(test_case, pass, pass ? "PASS" : "FAIL");
    }
    _release_test_file_record();

    return result->total == result->pass ? TEST_PASS : TEST_FAIL;
}

int main(int argc, const char *argv[])
{
    struct test_result result;
    enum test_status status;

    status = _test_search_file_record(files_search_test_cases,
                                      files_search_test_cases_size,
                                      &result);
    printf("%s (Total %d, Run %d, Pass %d)\n",
           status == TEST_PASS ? "PASS" : "FAIL",
           result.total,
           result.run,
           result.pass,
           test_status_str(status));

    return 0;
}
