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

#include "linux/types.h"
#include <stdlib.h>

static int kmalloc_detect_enable = 0;
static int kmalloc_detect_count;

void start_kmalloc_detect(void)
{
    kmalloc_detect_enable = 1;
    kmalloc_detect_count = 0;
}

void stop_kmalloc_detect(void)
{
    kmalloc_detect_enable = 0;
}

int get_kmalloc_count(void)
{
    return kmalloc_detect_count;
}

void *__wrap___kmalloc(size_t size, gfp_t flags)
{
    if (kmalloc_detect_enable) {
        kmalloc_detect_count++;
    }
    return malloc(size);
}

void __wrap_kfree(const void *objp)
{
    if (kmalloc_detect_enable) {
        kmalloc_detect_count--;
    }
    return free((void *)objp);
}
