/*
 * User Space mock for Kernel Functions Security Hash Locking Module
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

#include <stdlib.h>
#include <errno.h>

int __wrap_kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{
    errno = 0;
    unsigned long long int result = strtoull(s, NULL, base);

    if (errno != 0) {
        *res = 0;
        return -errno;
    }

    *res = result;
    return 0;
}
