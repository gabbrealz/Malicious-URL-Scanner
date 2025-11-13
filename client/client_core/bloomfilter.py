from bitarray import bitarray   # Bloom filters use bit arrays
import mmh3                     # For optimized, non-cryptographic hash functions
import math                     # For computing values

import constants as c


class BloomFilter:
    def __init__(self, entry_count: int):
        # Compute the size of the bit array based on the expected item count,
        # and a given false positive probability
        bitarray_size = -((entry_count+24) * math.log(c.BF_FP_PROBABILITY)) / (math.log(2)**2)

        # Compute the amount of hashes that must be done for each entry
        self.hash_count = max(1, int((bitarray_size/entry_count) * math.log(2)))

        # Initialize the bit array
        self.bit_array = bitarray(int(bitarray_size))
        self.bit_array.setall(0)

    # =================================================================================================
    # CORE FUNCTIONS ==================================================================================
    
    def add(self, key: bytes) -> None:
        # Hash the item multiple times into the bit array,
        # use i as the seed to give a different result each time
        for i in range(self.hash_count):
            digest = self.get_digest(key, i)
            self.bit_array[digest] = True


    def check(self, key: bytes) -> bool:
        # Hash the item multiple times and check the bit values
        # Hitting a 0 bit means the item is not in the set
        for i in range(self.hash_count):
            if not self.bit_array[self.get_digest(key, i)]:
                return False
        
        # If the check returns true, it may be a false positive
        return True
    
    # =================================================================================================
    # HELPER FUNCTIONS ================================================================================

    def get_digest(self, key: bytes, seed: int) -> int:
        return (mmh3.hash(key, seed=seed) & 0xFFFFFFFF) % len(self.bit_array)



if __name__ == "__main__":
    bloomfilter = BloomFilter(10)

    items = [
        "youtube", "instagram", "facebook", "daliri", "google",
        "ghibli", "callofduty", "deltaforce", "codmunity", "biniverse"
    ]

    for item in items:
        bloomfilter.add(item)

    print(bloomfilter.check("google.com"))