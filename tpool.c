/* Copyright (C) 2026 by Howard Chu.
 * http://www.highlandsun.com/hyc/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* simple thread pool */

#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include "tpool.h"

typedef struct tpool_task {
	tpool_starter *tt_func;
	void *tt_arg;
	struct tpool_task *tt_next;
} tpool_task;

static int tp_max_threads;
static int tp_num_threads;
static int tp_busy_threads;

static int tp_finished;

static pthread_mutex_t tp_mutex;
static pthread_cond_t tp_cond;

static tpool_task *tp_work_list;
static tpool_task *tp_task_list;

static void *
tpool_wrapper() {
	tpool_task *ttp, tt;

	pthread_mutex_lock(&tp_mutex);
	for (;;) {
		while (!tp_work_list && !tp_finished)
			pthread_cond_wait(&tp_cond, &tp_mutex);
		if (tp_finished) {
			tp_num_threads--;
			pthread_mutex_unlock(&tp_mutex);
			break;
		}
		ttp = tp_work_list;
		tp_work_list = ttp->tt_next;
		tt = *ttp;
		ttp->tt_next = tp_task_list;
		tp_task_list = ttp;
		tp_busy_threads++;
		pthread_mutex_unlock(&tp_mutex);
		tt.tt_func(tt.tt_arg);
		pthread_mutex_lock(&tp_mutex);
		tp_busy_threads--;
	}
	return NULL;
}

int tpool_init(int max_threads) {
	pthread_mutex_init(&tp_mutex, NULL);
	pthread_cond_init(&tp_cond, NULL);

	tp_max_threads = max_threads;
}

int tpool_submit(tpool_starter *func, void *arg) {
	tpool_task *ttp;

	pthread_mutex_lock(&tp_mutex);
	if (tp_task_list) {
		ttp = tp_task_list;
		tp_task_list = ttp->tt_next;
	} else {
		ttp = malloc(sizeof(tpool_task));
		if (!ttp)
			return ENOMEM;
	}
	ttp->tt_func = func;
	ttp->tt_arg = arg;
	ttp->tt_next = tp_work_list;
	tp_work_list = ttp;
	
	if (tp_num_threads < tp_max_threads) {
		if (tp_busy_threads == tp_num_threads) {
			pthread_t tid;
			if (pthread_create(&tid, NULL, tpool_wrapper, NULL))
				return errno;
			tp_num_threads++;
		}
	}
	pthread_mutex_unlock(&tp_mutex);
	pthread_cond_signal(&tp_cond);
	return 0;
}

void tpool_destroy() {
	tpool_task *ttp, *tt2;
	tp_finished = 1;
	pthread_cond_broadcast(&tp_cond);
	pthread_mutex_lock(&tp_mutex);
	while (tp_num_threads)
		pthread_cond_wait(&tp_cond, &tp_mutex);

	while(tp_work_list) {
		ttp = tp_work_list;
		tp_work_list = ttp->tt_next;
		free(ttp);
	}

	while(tp_task_list) {
		ttp = tp_task_list;
		tp_task_list = ttp->tt_next;
		free(ttp);
	}
}
