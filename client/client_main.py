from pathlib import Path
import os
import sys
sys.path.append(str(Path(__file__).resolve().parent/"client_core"))

from urllib.parse import quote
from validators import url as validate_url
import argparse

from rich.console import Console, Group
from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from rich import box
from pyfiglet import figlet_format as bigtext

from client import Client


clear_screen = lambda: os.system("cls" if os.name == "nt" else "clear")


def ask_option(console: Console) -> int:
    while True:
        option = console.input("[b i yellow]Enter Menu Option >[/b i yellow] ")
        if option == "" or len(option) > 1 or not option.isdigit():
            return 
        else: return int(option)



def url_is_valid(url: str) -> bool:
    if url == "": return False
    if not url.startswith(("http://", "https://")): url = "http://" + url
    return validate_url(url)

def ask_url(console: Console) -> str:
    url = console.input("[b i yellow]Enter a complete and valid URL >[/b i yellow] ")
    while not url_is_valid(url):
        url = console.input("[#FF4C4C]The given URL is [b]invalid[/b][/#FF4C4C]\n[b i yellow]Enter a complete and valid URL >[/b i yellow] ")
    return url


def option_1(console: Console, client: Client) -> None:
    url = ask_url(console)
    console.print()
    result = client.check_url(url)

    clear_screen()

    match result:
        case 0: consensus = "[b green]✅ The URL is safe![/b green]"
        case 1: consensus = "[b #FF4C4C]❌ The URL is a blacklisted site, not safe[/b #FF4C4C]"
        case 2: consensus = "The program cannot process your request at this time. Sorry!"

    url_panel = Panel(url, title="URL", box=box.ROUNDED, padding=(1,1))
    consensus_panel = Panel(consensus, title="Consensus", box=box.ROUNDED, padding=(1,1))

    results_panel = Panel(
        Align.center(Group(url_panel, consensus_panel), vertical="middle"),
        title = "[b bright_magenta]URL CHECK RESULTS[/b bright_magenta]",
        border_style = "magenta",
        box = box.ROUNDED,
        padding = (1,1),
        width = console.width
    )

    console.print(results_panel, justify="center")
    console.input("\n[b i yellow]Press Enter to go back...[b i yellow]")


def option_2(console: Console, client: Client) -> str:
    url = ask_url(console)
    console.print()
    result = client.blacklist_url(url)

    return "[green]Your request to blacklist a URL was successful![/green]" if result == 0 else \
           "[#FF4C4C]Your request to blacklist a URL failed[/#FF4C4C]"


def option_3(console: Console, client: Client) -> str:
    result = client.rebuild_bloomfilter(True)
    return "[green]Rebuilding the bloom filter was successful![/green]" if result == 0 else \
           "[#FF4C4C]Failed to build bloom filter[/#FF4C4C]"


def option_4(console: Console, client: Client) -> None:
    clear_screen()
    client.print_session_logs()
    console.input("\n[b i yellow]Press Enter to go back...[b i yellow]")


def option_5(console: Console, client: Client) -> None:
    clear_screen()
    client.print_server_logs()
    console.input("\n[b i yellow]Press Enter to go back...[b i yellow]")

def option_6(console: Console, client: Client) -> None:
    clear_screen()
    console.print(f"[b yellow]{bigtext("Thank You For Using GnarlyCursion URL Scanner!")}[/b yellow]\n")
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="localhost")
    args = parser.parse_args()


    menu_table = Table(
        title="[b u bright_magenta]PLEASE PICK AMONG THESE MENU OPTIONS[/b u bright_magenta]", title_justify="center",
        border_style="magenta",
        row_styles=["on #1c1c1c", "on #262626"],
        header_style="bold white on dark_magenta",
        padding=(0, 1)
    )
    menu_table.add_column("[b]Input[/b]", justify="center", style="white on blue")
    menu_table.add_column("[b]Description[/b]", style="white on blue")

    rows = [
        ("1", "Check if a URL is blacklisted"),
        ("2", "Submit a malicious URL for blacklisting"),
        ("3", "Rebuild the bloom filter with an updated list"),
        ("4", "Check the current session logs"),
        ("5", "Check server logs"),
        ("6", "End the session"),
    ]
    for row in rows: menu_table.add_row(*row)

    console = Console()
    clear_screen()
    console.print(f"[b yellow]{bigtext("Welcome to GnarlyCursion's URL Scanner!")}[/b yellow]\n")

    invalid_chars = r'\/:*?"<>|' if os.name == "nt" else '\0'

    name = ""
    while name == "" or any(char in name for char in invalid_chars):
        name = console.input("[b i yellow]To start, please provide a name for logging purposes >[/b i yellow] ")

    console.print()
    client = Client(quote(name), f"http://{args.host}:{args.port}", console)
    message = ""

    try:
        while True:
            clear_screen()
            console.print(menu_table, justify="center")
            if message:
                console.print(f"\n{message}\n", justify="center")
                message = ""
            else: console.print("Your bloom filter is not initialized" if client.bloom_filter is None else "")

            match ask_option(console):
                case 1: option_1(console, client)
                case 2: message = option_2(console, client)
                case 3: message = option_3(console, client)
                case 4: option_4(console, client)
                case 5: option_5(console, client)
                case 6: option_6(console, client)
                case _: message = "[#FF4C4C]Your input is not a menu option.[/#FF4C4C]"
 
    except BaseException as e:
        client.write_to_log(f"[SESSION] Session ended: ({type(e).__name__}) {e}", True)
        raise