from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent/"server_core"))

from fastapi import FastAPI, Request, Response, status
from contextlib import asynccontextmanager
import asyncio
import uvicorn

from datetime import datetime
from time import time
import argparse

from idx_reader import IndexReader, build_memtable_from_WAL
from idx_builder import flush_to_idx
import constants as c

# =================================================================================================
# HELPER FUNCTIONS ================================================================================

get_date = lambda: datetime.now().strftime("%Y-%m-%d")
get_time = lambda: datetime.now().strftime("%H:%M:%S")

def generate_activity_log(date: str) -> Path:
    time = get_time()

    file_path = Path(__file__).parent/"server_core"/"data"/"log"/"activity"/f"{date}.log"
    line_break = file_path.exists()

    with open(file_path, "a", encoding="utf-8") as log:
        log.write(f"{"\n" if line_break else ""}{time} - [SESSION] Server started\n")
    return file_path


def write_to_log(request: Request, client_name: str, message: str, line_break: bool = False) -> None:
    with open(request.app.state.log_path, "a", encoding="utf-8") as log:
        log.write(f"{"\n" if line_break else ""}{get_time()} - [CLIENT: {client_name}] {message}\n")

# =================================================================================================
# SERVER CONTEXT ==================================================================================

@asynccontextmanager
async def lifespan(server: FastAPI):
    # Create index file readers per partition
    server.state.idx_readers = [IndexReader(i) for i in range(1, c.PARTITIONS+1)]
    # Load write-ahead logs into memory with Memtables
    server.state.memtables = [build_memtable_from_WAL(i) for i in range(1, c.PARTITIONS+1)]
    # Create a log file or use an existing one
    server.state.date = get_date()
    server.state.log_path = generate_activity_log(server.state.date)
    # Create locks to prevent race conditions
    server.state.log_lock = asyncio.Lock()
    server.state.idx_lock = asyncio.Lock()
    server.state.memtable_lock = asyncio.Lock()

    yield   # Let the server run

    # Write to log
    if get_date() != server.state.date:
        server.state.date = get_date()
        server.state.log_path = Path(__file__).parent/"server_core"/"data"/"log"/"activity"/f"{server.state.date}.log"
        line_break = False
    else: line_break = True

    with open(server.state.log_path, "a", encoding="utf-8") as log:
        log.write(f"{"\n" if line_break else ""}{get_time()} - [SESSION] Server shutting down")


server = FastAPI(lifespan=lifespan, root_path=c.CONTEXT_PATH)

# =================================================================================================
# API ENDPOINTS ===================================================================================

@server.get("/fetch-hashes")
async def fetch_hashes(client: str, prefix: str, request: Request):
    bytes_prefix = bytes.fromhex(prefix)
    
    async with request.app.state.log_lock:
        if get_date() != request.app.state.date:
            request.app.state.date = get_date()
            request.app.state.log_path = generate_activity_log()
        write_to_log(request, client, f"[GET] Retrieving full hashes for hash prefix {prefix}", True)

    start_time = time()

    lower_bound = bytes_prefix + b"\x00"*(c.HASH_SIZE-c.PREFIX_SIZE)
    upper_bound = bytes_prefix + b"\xFF"*(c.HASH_SIZE-c.PREFIX_SIZE)

    partition = c.PARTITION_NUM(bytes_prefix[0])

    async with request.app.state.memtable_lock:
        hashes = request.app.state.memtables[partition].range_lookup(lower_bound, upper_bound)
    async with request.app.state.idx_lock:
        hashes.extend(request.app.state.idx_readers[partition].range_lookup(lower_bound, upper_bound))

    time_taken = time() - start_time
    async with request.app.state.log_lock:
        write_to_log(request, client, f"[GET] Successfully fetched hashes with prefix {bytes_prefix} in {time_taken:.4f} seconds")

    return Response(content=bytes(hashes), media_type="application/octet-stream")


@server.post("/submit-malicious-url")
async def submit_malicious_url(client: str, url: str, request: Request):
    async with request.app.state.log_lock:
        if get_date() != request.app.state.date:
            request.app.state.date = get_date()
            request.app.state.log_path = generate_activity_log()
        write_to_log(request, client, "[POST] Blacklisting a URL hash", True)

    url_hash = bytes.fromhex(url)
    partition = c.PARTITION_NUM(url_hash[0])

    async with request.app.state.log_lock:
        write_to_log(request, client, "[POST] Checking if URL already exists")
        
    async with request.app.state.idx_lock:
        if request.app.state.idx_readers[partition].contains_hash(url_hash):
            async with request.app.state.log_lock:
                write_to_log(request, client, "[POST] URL already exists in the blacklist")
            return Response(content="Bad request: URL is already blacklisted", status_code=status.HTTP_400_BAD_REQUEST)

    async with request.app.state.memtable_lock:
        memtable = request.app.state.memtables[partition]

        if url_hash in memtable:
            async with request.app.state.log_lock:
                write_to_log(request, client, "[ERROR] URL already exists")
            return Response(content="Bad request: URL is already blacklisted", status_code=status.HTTP_400_BAD_REQUEST)
        
        memtable.insert(url_hash)
        wal_path = Path(__file__).resolve().parent/"server_core"/"data"/"log"/"write_ahead"/f"partition{partition}.bin"

        if len(memtable) >= c.HASHES_PER_IDX:
            async with request.app.state.log_lock:
                write_to_log(request, client, f"[POST] Flushing partition {partition} memtable to new index file")

            start_time = time()

            async with request.app.state.idx_lock:
                flush_to_idx(memtable, partition)
            with open(wal_path, "w") as f:
                pass

            async with request.app.state.log_lock:
                write_to_log(request, client, f"[POST] Flushed the partition {partition} memtable in {time()-start_time:.4f} seconds")
        else:
            async with request.app.state.log_lock:
                write_to_log(request, client, "[POST] Writing the hash into the write-ahead log")
            with open(wal_path, "ab") as f:
                f.write(url_hash)

    async with request.app.state.log_lock:
        write_to_log(request, client, f"[POST] URL successfully blacklisted")


@server.get("/fetch-prefixes/memtable")
async def get_memtable_hash_prefixes(client: str, partition: int, request: Request):
    async with request.app.state.log_lock:
        if get_date() != request.app.state.date:
            request.app.state.date = get_date()
            request.app.state.log_path = generate_activity_log()
        write_to_log(request, client, f"[GET] Fetching all hash prefixes in the partition {partition} memtable")

    start_time = time()
    async with request.app.state.memtable_lock:
        hash_prefixes = bytearray()
        for url_hash in request.app.state.memtables[partition-1]:
            hash_prefixes.extend(url_hash[:4])

    async with request.app.state.log_lock:
        write_to_log(request, client, f"[GET] Successfully fetched all hash prefixes in the partition {partition} memtable in {time()-start_time:.4f} seconds")

    return Response(content=bytes(hash_prefixes), media_type="application/octet-stream")


@server.get("/fetch-prefixes/index")
async def get_idx_hash_prefixes(client: str, partition: int, request: Request):
    async with request.app.state.log_lock:
        if get_date() != request.app.state.date:
            request.app.state.date = get_date()
            request.app.state.log_path = generate_activity_log()
        write_to_log(request, client, f"[GET] Fetching all hash prefixes in the partition {partition} index files")

    start_time = time()
    async with request.app.state.idx_lock:
        hash_prefixes = request.app.state.idx_readers[partition-1].get_all_hash_prefixes()

    async with request.app.state.log_lock:
        write_to_log(request, client, f"[GET] Successfully fetched all hash prefixes in the partition {partition} index files in {time()-start_time:.4f} seconds")

    return Response(content=bytes(hash_prefixes), media_type="application/octet-stream")


@server.get("/fetch-blacklist-metadata")
async def get_blacklist_size(client: str, request: Request):
    async with request.app.state.log_lock:
        if get_date() != request.app.state.date:
            request.app.state.date = get_date()
            request.app.state.log_path = generate_activity_log()
        write_to_log(request, client, "[GET] Fetching blacklist metadata", True)

    start_time = time()
    size = sum(reader.get_idx_file_amount()*c.HASHES_PER_IDX for reader in request.app.state.idx_readers)

    async with request.app.state.memtable_lock:
        for memtable in request.app.state.memtables:
            size += len(memtable)

    async with request.app.state.log_lock:
        write_to_log(request, client, f"[GET] Done fetching metadata in {time()-start_time:.4f} seconds")

    return [size, c.PARTITIONS]


@server.get("/get-logs")
async def get_logs(client: str, request: Request):
    async with request.app.state.log_lock:
        if get_date() != request.app.state.date:
            request.app.state.date = get_date()
            request.app.state.log_path = generate_activity_log()
        write_to_log(request, client, "[GET] Fetching server logs", True)

        with open(request.app.state.log_path, "r", encoding="utf-8") as f:
            return f.readlines()

# =================================================================================================
# RUN THE SERVER ==================================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    
    uvicorn.run("server_main:server", host=args.host, port=args.port)