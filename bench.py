# -*- coding: utf-8 -*-

import random
import perf
import iota
import pearldiver


ALPHABETS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ9'
TRYTE_LENGTH = 2673


def get_random_trytes(seed=None):
    if seed:
        random.seed(seed)
    return iota.TryteString(''.join(
        [random.choice(ALPHABETS) for _ in range(TRYTE_LENGTH)]))


def run_diver(trytes, magnitude, cores):
    diver = pearldiver.PearlDiver()
    diver.search(trytes.as_trits(), magnitude, cores)


def bench_magnitude_9_cores_1(trytes):
    run_diver(trytes, 9, 1)


def bench_magnitude_9_cores_4(trytes):
    run_diver(trytes, 9, 4)


def bench_magnitude_9_cores_8(trytes):
    run_diver(trytes, 9, 8)


if __name__ == '__main__':
    runner = perf.Runner()
    trytes = get_random_trytes()
    runner.bench_func('m9c8', bench_magnitude_9_cores_8, trytes)
