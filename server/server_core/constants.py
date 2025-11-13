HASHES_PER_IDX = 15625
HASH_SIZE = 32
PREFIX_SIZE = 4
PARTITIONS = 4
PARTITION_NUM = lambda byte: byte >> 6  # type (int) -> int
CONTEXT_PATH = "/gnarlycursion-api"


if __name__ == "__main__":
    print(PARTITION_NUM(b'\x00'))