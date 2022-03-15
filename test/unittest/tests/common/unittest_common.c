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

#include "unittest_common.h"

const char *test_status_str(enum test_status status) {
    switch (status) {
        case TEST_PASS:
            return "PASS";
        case TEST_FAIL:
            return "FAIL";
        case TEST_INVALID_ARG_NULL_POINTER:
            return "NULL pointer as argument";
        case TEST_MALLOC_FAIL:
            return "Fail to allocate memory";
        case TEST_SETUP_FAIL:
            return "Fail to setup test";
        default:
            return "Unknown result";
    }
}
