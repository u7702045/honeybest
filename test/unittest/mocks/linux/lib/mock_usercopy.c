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

#include <string.h>

unsigned long __wrap__copy_from_user(void *to, const void *from, unsigned n)
{
    memcpy(to, from, n);
    return n;
}
