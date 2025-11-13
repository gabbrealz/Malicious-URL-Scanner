from pathlib import Path
import mmap

import constants as c
from memtable import MemTable


def build_memtable_from_WAL(partition_num: int) -> MemTable:
    wal_path = Path(__file__).resolve().parent/"data"/"log"/"write_ahead"/f"partition{partition_num}.bin"
    wal_path.touch(exist_ok=True)
    
    memtable = MemTable()
    if wal_path.stat().st_size == 0:
        return memtable
    
    with open(wal_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for offset in range(0, len(mm), c.HASH_SIZE):
            memtable.insert(mm[offset:offset + c.HASH_SIZE])

    return memtable


class IndexReader:
    def __init__(self, partition_number: int):
        self.dir_path = Path(__file__).resolve().parent/"data"/"db"/f"partition{partition_number}"

    
    def range_lookup(self, lower_bound: bytes, upper_bound: bytes) -> bytearray:
        results = bytearray()
        hashes_per_idx = c.HASHES_PER_IDX
        hash_size = c.HASH_SIZE

        idx_num = 1
        file_path = self.dir_path/f"idx_{idx_num:03d}.bin"

        while Path(file_path).is_file():
            with open(file_path, "rb") as f:
                data = f.read()

            low, high = 0, hashes_per_idx - 1
            while low < high:
                mid = (low + high) >> 1
                start = mid * hash_size
                url_hash = data[start:start+hash_size]

                if lower_bound > url_hash: low = mid + 1
                else: high = mid

            lower_index = low

            low, high = 0, hashes_per_idx - 1
            while low < high:
                mid = (low + high) >> 1
                start = mid * hash_size
                url_hash = data[start:start + hash_size]

                if upper_bound >= url_hash: low = mid + 1
                else: high = mid

            upper_index = low

            results.extend(data[lower_index*hash_size : upper_index*hash_size])
            idx_num += 1
            file_path = self.dir_path/f"idx_{idx_num:03d}.bin"
        
        return results
    

    def contains_hash(self, key: bytes) -> bool:
        hashes_per_idx = c.HASHES_PER_IDX
        hash_size = c.HASH_SIZE

        idx_num = 1
        file_path = self.dir_path/f"idx_{idx_num:03d}.bin"

        while Path(file_path).is_file():
            with open(file_path, "rb") as f:
                data = f.read()

            low, high = 0, hashes_per_idx - 1
            while low <= high:
                mid = (low+high) >> 1
                start = mid*hash_size
                url_hash = data[start:start+hash_size]

                if key == url_hash: return True
                elif key < url_hash: high = mid-1
                else: low = mid+1

            idx_num += 1
            file_path = self.dir_path/f"idx_{idx_num:03d}.bin"

        return False
    

    def get_all_hash_prefixes(self) -> bytearray:
        byte_records = bytearray()
        idx_num = 1
        file_path = self.dir_path/f"idx_{idx_num:03d}.bin"

        while Path(file_path).is_file():
            with open(file_path, "rb") as f:
                while sha256_hash := f.read(c.HASH_SIZE):
                    byte_records.extend(sha256_hash[:4])
            idx_num += 1
            file_path = self.dir_path/f"idx_{idx_num:03d}.bin"

        return byte_records
    

    def get_idx_file_amount(self) -> int:
        idx_num = 1
        file_path = self.dir_path/f"idx_{idx_num:03d}.bin"
        while Path(file_path).is_file():
            idx_num += 1
            file_path = self.dir_path/f"idx_{idx_num:03d}.bin"

        return idx_num - 1