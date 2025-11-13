from pathlib import Path
from hashlib import sha256
import pickle
import requests
import re

from datetime import datetime
from time import time, sleep

from rich.console import Console
from rich.text import Text

from bloomfilter import BloomFilter
import constants as c


class Client:
    get_date = lambda: datetime.now().strftime("%Y-%m-%d")
    get_time = lambda: datetime.now().strftime("%H:%M:%S")
    
    def __init__(self, name: str, base_url: str, console: Console):
        self.name = name
        self.base_url = base_url
        self.console = console
        self.date = Client.get_date()
        
        self.log_path = Path(__file__).resolve().parent/"data"/"log"

        sequential_id = 0
        while Path.exists(self.log_path/f"{name}-{sequential_id:03d}.log"):
            sequential_id += 1

        self.log_path = self.log_path/f"{name}-{sequential_id:03d}.log"
        self.write_to_log(f"[SESSION] Session started for {name}")

        self.filter_filepath = Path(__file__).resolve().parent/"data"/"local_data"/"bloom_filter.pkl"

        if self.filter_filepath.exists():
            with open(self.filter_filepath, "rb") as bf:
                self.bloom_filter = pickle.load(bf)
            self.write_to_log(f"[SESSION] Successfully loaded the local bloom filter into memory")
        else:
            self.write_to_log(f"[SESSION] Bloom filter could not be found, requesting server for a rebuild")
            result = self.rebuild_bloomfilter()
            if result == 1:
                self.write_to_log(f"[SESSION] Failed to load the local bloom filter", True)
            else:
                self.write_to_log(f"[SESSION] Successfully loaded the local bloom filter into memory", True)


    def check_url(self, url: str) -> int:
        self.write_to_log(f"[CHECK] Checking URL safety for \"{url}\"", True)
        start_time = time()

        url_hash = sha256(url.encode("utf-8")).digest()
        hash_prefix = url_hash[:c.PREFIX_SIZE]

        with self.console.status("[i]Checking with local bloom filter...[/i]", spinner="point") as status:
            if self.bloom_filter is None:
                self.write_to_log(f"[CHECK] Bloom filter has not been initialized, requesting confirmation from the server instead")
            elif self.bloom_filter.check(hash_prefix):
                self.write_to_log(f"[CHECK] The URL may be malicious after a bloom filter check, requesting confirmation from the server")
            else:
                self.write_to_log(f"[CHECK] Bloom filter confirms URL is safe in {time()-start_time:.4f} seconds")
                return 0

            status.update("[i]Checking with server...[/i]")
            start_time = time()

            try:
                response = requests.get(f"{self.base_url}{c.CONTEXT_PATH}/fetch-hashes?client={self.name}&prefix={hash_prefix.hex()}")
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                self.write_to_log(f"[ERROR] {e}")
                return 2

            status.update("[i]Processing server response...[/i]")

            hashes = response.content
            if url_hash in hashes:
                self.write_to_log(f"[CHECK] The URL is confirmed malicious after {time()-start_time:.4f} seconds")
                return 1
        
        self.write_to_log(f"[CHECK] The URL is determined safe after {time()-start_time:.4f} seconds")
        return 0
    

    def blacklist_url(self, url: str) -> int:
        self.write_to_log(f"[POST] Submitting \"{url}\" to be blacklisted", True)

        url_hash = sha256(url.encode("utf-8")).digest()

        self.console.print()
        with self.console.status("[i]Submitting malicious URL to server...[/i]", spinner="point") as status:
            start_time = time()
            try:
                response = requests.post(f"{self.base_url}{c.CONTEXT_PATH}/submit-malicious-url?client={self.name}&url={url_hash.hex()}")
                response.raise_for_status()

                self.bloom_filter.add(url_hash[:4])
                status.update("[i]Updating bloom filter[/i]")
                
                with open(self.filter_filepath, "wb") as bf:
                    pickle.dump(self.bloom_filter, bf)

                self.write_to_log(f"[POST] Successfully blacklisted the URL in {time()-start_time:.4f} seconds")

            except requests.exceptions.HTTPError as e:
                self.write_to_log(f"[ERROR] {e}")
                self.write_to_log("[POST] Request to blacklist the URL has failed")
                self.bloom_filter = None
                return 1
            
        return 0
    

    def rebuild_bloomfilter(self, auto: bool = False) -> int:
        self.write_to_log("[REBUILD] Requesting the full list of hash prefixes from the server", True)

        if not auto:
            self.console.print("[b i yellow]A bloom filter does not exist on your machine\nBeginning to build a new one[/b i yellow]")
            self.console.input("[b i yellow]Press Enter to start...[/b i yellow]")
        
        self.console.print()
        with self.console.status("[i]Fetching server blacklist metadata...[/i]", spinner="point") as status:
            start_time = time()
            try:
                response = requests.get(f"{self.base_url}{c.CONTEXT_PATH}/fetch-blacklist-metadata?client={self.name}")
                response.raise_for_status()

                entry_count, partitions = response.json()
                self.bloom_filter = BloomFilter(entry_count)

                partial_request_urls = (
                    f"{self.base_url}{c.CONTEXT_PATH}/fetch-prefixes/memtable?client={self.name}&partition=",
                    f"{self.base_url}{c.CONTEXT_PATH}/fetch-prefixes/index?client={self.name}&partition="
                )

                for i in range(1, partitions+1):
                    status.update(f"[i]Fetching list of malicious URLs from the server... ({i}/{partitions})[/i]")
                    for partial_request_url in partial_request_urls:
                        response = requests.get(partial_request_url+str(i))
                        response.raise_for_status()

                        prefix_list = response.content
                        for j in range(0, len(prefix_list), c.PREFIX_SIZE):
                            self.bloom_filter.add(prefix_list[j:j + c.PREFIX_SIZE])

            except requests.exceptions.HTTPError as e:
                self.write_to_log(f"[ERROR] {e}")
                self.bloom_filter = None
                return 1

            self.write_to_log(f"[REBUILD] Now saving the bloom filter into client's local data")
            with open(self.filter_filepath, "wb") as bf:
                pickle.dump(self.bloom_filter, bf)

            status.update("[b green]Done![/b green]")
            sleep(1.75)

        self.write_to_log(f"[REBUILD] Finished building bloom filter in {time()-start_time:.4f} seconds")
        return 0


    def print_session_logs(self) -> None:
        tag_colors = [
            ("SESSION", "yellow"),
            ("CHECK", "magenta"),
            ("REBUILD", "cyan"),
            ("POST", "green"),
            ("ERROR", "red bold"),
        ]

        tag_patterns = [
            (re.compile(fr"\[{tag}\]"), f"[{color}][{tag}][/{color}]")
            for tag, color in tag_colors
        ]
        content_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.*)")
        seconds_pattern = re.compile(r"(\d+.\d+ seconds)")
        safe_pattern = re.compile(r"\b(safe)\b", flags=re.IGNORECASE)
        malicious_pattern = re.compile(r"\b(malicious|failed)\b", flags=re.IGNORECASE)

        with open(self.log_path, "r", encoding="utf-8") as log:
            for line in log:
                if not line:
                    self.console.print()
                    continue
                line = line.strip()

                match = content_pattern.match(line)
                if match: date, rest = match.groups()
                else: date, rest = "", line

                for pattern, replacement in tag_patterns:
                    rest = pattern.sub(replacement, rest)

                rest = seconds_pattern.sub(r"[bold blue]\1[/bold blue]", rest)
                rest = safe_pattern.sub(r"[green]\1[/green]", rest)
                rest = malicious_pattern.sub(r"[red bold]\1[/red bold]", rest)

                rest = rest.replace("[", "[[").replace("]", "]]")
                rest = rest.replace("[[", "[")
                rest = rest.replace("]]", "]")

                final_text = Text()
                if date:
                    final_text.append(date, style="dim")
                    final_text.append(" - ")
                final_text.append(Text.from_markup(rest))

                self.console.print(final_text, highlight=False)


    def print_server_logs(self) -> None:
        tag_colors = [
            ("GET", "cyan"),
            ("POST", "green"),
            ("ERROR", "red bold"),
        ]

        tag_patterns = [
            (re.compile(fr"\[{tag}\]"), f"[{color}][{tag}][/{color}]")
            for tag, color in tag_colors
        ]
        content_pattern = re.compile(r"^(\d{2}:\d{2}:\d{2}) - (.*)")
        seconds_pattern = re.compile(r"(\d+.\d+ seconds)")
        green_pattern = re.compile(r"\b(successfully|done)\b", flags=re.IGNORECASE)

        with self.console.status("[i]Fetching server logs...[/i]", spinner="point") as status:
            try:
                response = requests.get(f"{self.base_url}{c.CONTEXT_PATH}/get-logs?client={self.name}")
                response.raise_for_status()
                logs = response.json()
            except Exception as e:
                self.console.print("[b red]Sorry! Cannot display server logs right now[/b red]", justify="center")
                return

        for line in logs:
            if not line:
                self.console.print()
                continue
            line = line.strip()

            match = content_pattern.match(line)
            if match: time, rest = match.groups()
            else: time, rest = "", line

            for pattern, replacement in tag_patterns:
                rest = pattern.sub(replacement, rest)

            rest = seconds_pattern.sub(r"[bold blue]\1[/bold blue]", rest)
            rest = green_pattern.sub(r"[green]\1[/green]", rest)

            rest = rest.replace("[", "[[").replace("]", "]]")
            rest = rest.replace("[[", "[")
            rest = rest.replace("]]", "]")

            final_text = Text()
            if time:
                final_text.append(time, style="dim")
                final_text.append(" - ")
            final_text.append(Text.from_markup(rest))

            self.console.print(final_text, highlight=False)


    def write_to_log(self, message: str, line_break: bool = False) -> None:
        with open(self.log_path, "a", encoding="utf-8") as log:
            log.write(f"{"\n" if line_break else ""}{Client.get_date()} {Client.get_time()} - {message}\n")