from hashlib import sha256
from csv import reader as csv_reader
from pathlib import Path
import sys
import os

from memtable import MemTable
from constants import PARTITION_NUM, HASHES_PER_IDX


def build_idx(memtable: MemTable, out_path: str) -> None:
    # Simple binary file, simply write the hashes in sequence
    with open(out_path, "wb") as f:
        for h in memtable: f.write(h)


def flush_to_idx(memtable: MemTable, partition: int) -> None:
    out_dir = Path(__file__).resolve().parent/"data"/"db"/f"partition{partition}"

    idx_num = 1
    out_path = out_dir/f"idx_{idx_num:03d}.bin"
    while Path(out_path).exists():
        idx_num += 1
        out_path = out_dir/f"idx_{idx_num:03d}.bin"

    build_idx(memtable, out_path)

# ============================================================================================================
# NOTE: This script from here and below is not part of the app itself, but a script used to set up the data
# The purpose of this function is to take the data set of malicious URLs gathered online
# hash them using SHA-256, put them in their respective key ranges (partitions),
# sort them lexicographically, then write them into binary files, each containing 15,625 hashes.


def build_memtables_from_dataset(root_path: str) -> list[list[MemTable]]:
    # Resolve the path to the data set
    dataset_path = root_path/"data"/"malicious_urls.csv"

    # Initialize partitions
    partitions = [[MemTable() for _ in range(4)]]
    # Keeps track of which is the current table for a partition
    index = [0,0,0,0]

    # Open the csv file and create a reader object
    with open(dataset_path, "r", newline="", encoding="utf-8") as f:
        reader = csv_reader(f)
        # Skip the header row
        next(reader)

        for row in reader:
            digest = sha256(row[0].encode("utf-8")).digest()
            # Divide the first byte of the hash by 64 to determine which partition it belongs to
            partition = PARTITION_NUM(digest[0])

            # Insert the hash
            partitions[index[partition]][partition].insert(digest)

            # Check if the table has reached the limit
            if len(partitions[index[partition]][partition]) >= HASHES_PER_IDX:
                # If needed, add another list of memtables if a partition's table has reached their limit
                if len(partitions)-1 <= index[partition]:
                    partitions.append([MemTable() for _ in range(4)])

                index[partition] += 1   # Update the index so that it points to the correct memtable

    return partitions


if __name__ == "__main__":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

    ROOT_PATH = Path(__file__).resolve().parent.parent.parent
    memtables = build_memtables_from_dataset(ROOT_PATH)

    for folder_name in [ROOT_PATH/"server"/"server_core"/"data"/"db"/f"partition{i}" for i in range(1, 5)]:
        os.makedirs(folder_name, exist_ok=True)

    # Save the memtables into binary files
    for i in range(len(memtables)):
        for j in range(4):
            # If the memtable has the expected size, write it into a binary file
            if len(memtables[i][j]) >= HASHES_PER_IDX:
                build_idx(memtables[i][j], ROOT_PATH/"server"/"server_core"/"data"/"db"/f"partition{j+1}"/f"idx_{i+1:03d}.bin")
            # If memtable is still small, write it into a binary file as a Write-ahead Log
            elif len(memtables[i][j]) > 0:
                build_idx(memtables[i][j], ROOT_PATH/"server"/"server_core"/"data"/"log"/"write_ahead"/f"partition{j+1}.bin")