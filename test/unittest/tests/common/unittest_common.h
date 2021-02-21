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

#if !defined(MOXA_UNITTEST_COMMON_H)
#define MOXA_UNITTEST_COMMON_H

struct test_result {
    int total;
    int run;
    int pass;
};

enum test_status {
    TEST_PASS = 0,
    TEST_FAIL,
    TEST_INVALID_ARG_NULL_POINTER,
    TEST_MALLOC_FAIL,
    TEST_SETUP_FAIL,
};

extern const char *test_status_str(enum test_status status);

#endif
