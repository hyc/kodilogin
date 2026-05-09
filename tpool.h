/* Copyright (C) 2026 by Howard Chu.
 * http://www.highlandsun.com/hyc/
 *
 * You may distribute this program under the terms of the
 * GNU General Public License version 2.
 */

/* simple thread pool */

typedef void * (tpool_starter)(void *arg);

int tpool_submit(tpool_starter *func, void *arg);

int tpool_init(int max_threads);
void tpool_destroy(void);
