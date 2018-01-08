# -*- coding: utf-8 -*-

import iota
import numpy as np
from ctypes import c_long


L64 = 0xFFFFFFFFFFFFFFFF


class PearlDiver:
    TRANSACTION_LENGTH = 8019
    CURL_HASH_LENGTH = 243
    CURL_STATE_LENGTH = CURL_HASH_LENGTH * 3

    HIGH_BITS = -1
    LOW_BITS = 0

    def search(self, tx_trits, min_weight_magnitude, cores):
        if len(tx_trits) != self.TRANSACTION_LENGTH:
            raise ValueError(
                'Invalid transaction trits length: %d' % len(tx_trits))

        if (min_weight_magnitude < 0 or
                min_weight_magnitude > self.CURL_HASH_LENGTH):
            raise ValueError(
                'Invalid min weight magnitude: %d' % min_weight_magnitude)

        offset = 0
        mid_curl_state_low = np.array([0] * self.CURL_STATE_LENGTH, dtype=np.int64)
        mid_curl_state_high = np.array([0] * self.CURL_STATE_LENGTH, dtype=np.int64)
        for i in range(self.CURL_HASH_LENGTH, self.CURL_STATE_LENGTH):
            mid_curl_state_low[i] = self.HIGH_BITS
            mid_curl_state_high[i] = self.HIGH_BITS
        times = (self.TRANSACTION_LENGTH - self.CURL_HASH_LENGTH) // self.CURL_HASH_LENGTH
        for i in range(times):
            for j in range(self.CURL_HASH_LENGTH):
                if tx_trits[offset] == 0:
                    mid_curl_state_low[j] = self.HIGH_BITS
                    mid_curl_state_high[j] = self.HIGH_BITS
                elif tx_trits[offset] == 1:
                    mid_curl_state_low[j] = self.LOW_BITS
                    mid_curl_state_high[j] = self.HIGH_BITS
                else:
                    mid_curl_state_low[j] = self.HIGH_BITS
                    mid_curl_state_high[j] = self.LOW_BITS
                offset += 1
            self.transform(mid_curl_state_low, mid_curl_state_high)

        for i in range(162):
            mid_curl_state_low[i] = self.HIGH_BITS if tx_trits[offset] != 1 else self.LOW_BITS
            mid_curl_state_high[i] = self.HIGH_BITS if tx_trits[offset] != -1 else self.LOW_BITS
            offset += 1

        mid_curl_state_low[162 + 0] = c_long(0xdb6db6db6db6db6d).value
        mid_curl_state_high[162 + 0] = c_long(0xb6db6db6db6db6db).value
        mid_curl_state_low[162 + 1] = c_long(0xf1f8fc7e3f1f8fc7).value
        mid_curl_state_high[162 + 1] = c_long(0x8fc7e3f1f8fc7e3f).value
        mid_curl_state_low[162 + 2] = c_long(0x7fffe00ffffc01ff).value
        mid_curl_state_high[162 + 2] = c_long(0xffc01ffff803ffff).value
        mid_curl_state_low[162 + 3] = c_long(0xffc0000007ffffff).value
        mid_curl_state_high[162 + 3] = c_long(0x3fffffffffffff).value

        mcscl = np.copy(mid_curl_state_low)
        mcsch = np.copy(mid_curl_state_high)

        curl_state_low = np.array([0] * self.CURL_STATE_LENGTH, dtype=np.int64)
        curl_state_high = np.array([0] * self.CURL_STATE_LENGTH, dtype=np.int64)

        mask = 0
        out_mask = np.int64(1)
        while True:
            self.increment(mcscl, mcsch,
                           162 + (self.CURL_HASH_LENGTH // 9) * 2,
                           self.CURL_HASH_LENGTH)
            curl_state_low = np.copy(mcscl)
            curl_state_high = np.copy(mcsch)
            self.transform(curl_state_low, curl_state_high)

            mask = self.HIGH_BITS
            for i in range(min_weight_magnitude-1, -1, -1):
                mask &= ~(curl_state_low[self.CURL_HASH_LENGTH - 1 - i] ^
                          curl_state_high[self.CURL_HASH_LENGTH - 1 - i])
                if mask == 0:
                    break

            if mask == 0:
                continue

            while out_mask & mask == 0:
                out_mask <<= 1
            for i in range(self.CURL_HASH_LENGTH):
                v = 1 if mcscl[i] & out_mask == 0 else -1 if mcsch[i] & out_mask == 0 else 0
                tx_trits[self.TRANSACTION_LENGTH - self.CURL_HASH_LENGTH + i] = v
            break

    def transform(self, curl_state_low, curl_state_high):
        curl_scratchpad_index = 0
        for _ in range(iota.crypto.pycurl.NUMBER_OF_ROUNDS):
            curl_scratchpad_low = np.copy(curl_state_low)
            curl_scratchpad_high = np.copy(curl_state_high)

            for curl_state_index in range(self.CURL_STATE_LENGTH):
                alpha = curl_scratchpad_low[curl_scratchpad_index]
                beta = curl_scratchpad_high[curl_scratchpad_index]
                if curl_scratchpad_index < 365:
                    curl_scratchpad_index += 364
                else:
                    curl_scratchpad_index += -365

                gamma = curl_scratchpad_high[curl_scratchpad_index]
                delta = (alpha | (~gamma)) & (curl_scratchpad_low[curl_scratchpad_index] ^ beta)
                curl_state_low[curl_state_index] = ~delta
                curl_state_high[curl_state_index] = (alpha ^ gamma) | delta

    def increment(self, mid_curl_state_copy_low, mid_curl_state_copy_high,
                  from_index, to_index):
        for i in range(from_index, to_index):
            if mid_curl_state_copy_low[i] == self.LOW_BITS:
                mid_curl_state_copy_low[i] = self.HIGH_BITS
                mid_curl_state_copy_high[i] = self.LOW_BITS
            else:
                if mid_curl_state_copy_high[i] == self.LOW_BITS:
                    mid_curl_state_copy_high[i] = self.HIGH_BITS
                else:
                    mid_curl_state_copy_low[i] = self.LOW_BITS
                break
