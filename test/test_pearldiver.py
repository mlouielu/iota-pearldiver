# -*- coding: utf-8 -*-

import random
import unittest

import iota
import pearldiver


ALPHABETS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ9'
HASH_LENGTH = iota.crypto.pycurl.HASH_LENGTH


class PearlDiverTest(unittest.TestCase):
    TRYTE_LENGTH = 2673
    MIN_WEIGHT_MAGNITUDE = 9
    NUM_CORES = -1

    def setUp(self):
        self.pearldiver = pearldiver.PearlDiver()
        self.hash_trits = [0] * HASH_LENGTH

    def test_random_tryte_hash(self):
        trytes = self.get_random_trytes()
        hash = self.get_hash_for(trytes)
        self.assertTrue(
            self.is_all_nines(
                hash[HASH_LENGTH // 3 - self.MIN_WEIGHT_MAGNITUDE // 3:]))

    def get_hash_for(self, trytes):
        curl = iota.crypto.pycurl.Curl()
        trits = trytes.as_trits()
        self.pearldiver.search(trits,
                               self.MIN_WEIGHT_MAGNITUDE, self.NUM_CORES)
        curl.absorb(trits)
        curl.squeeze(self.hash_trits)
        curl.reset()

        return iota.Hash.from_trits(self.hash_trits)

    def get_random_trytes(self):
        return iota.TryteString(''.join(
            [random.choice(ALPHABETS) for _ in range(self.TRYTE_LENGTH)]))

    def is_all_nines(self, hash):
        return set(hash) == {b'9'}
