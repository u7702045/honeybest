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

#if !defined(MOXA_UNITTEST_MOCK_LINUX_MM_SLAB_H)
#define MOXA_UNITTEST_MOCK_LINUX_MM_SLAB_H

extern void start_kmalloc_detect(void);
extern void stop_kmalloc_detect(void);
extern int get_kmalloc_count(void);

#endif
