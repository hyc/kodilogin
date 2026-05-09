typedef void * (tpool_starter)(void *arg);

int tpool_submit(tpool_starter *func, void *arg);

int tpool_init(int max_threads);
void tpool_destroy(void);
