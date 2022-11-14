from multiprocessing.pool import ThreadPool as Pool
from multiprocessing import Pool
import timeit
pool_size = 7  # your "parallelness"
def worker(item):
    try:
        for i in range(100000000):
            i+item
    except:
        print('error with item')

pool = Pool(pool_size)

items = [1,2,3,4,5,6,7]

start = timeit.default_timer()

for item in items:
    pool.apply_async(worker, (item,))
pool.close()
pool.join()
# time end
stop = timeit.default_timer()

print('Time: ', stop - start)

# time start
start = timeit.default_timer()

for item in items:
    for i in range(100000000):
        i+item
# time end
stop = timeit.default_timer()

print('Time: ', stop - start)
