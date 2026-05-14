import sys
import hashlib
import json
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box
from rich.columns import Columns

from hashcrack import __version__
from hashcrack.detector import detect_hash, classify_by_length, HASH_PATTERNS
from hashcrack.lookup import lookup_hash, generate_hash, verify_hash

console = Console()
err_console = Console(stderr=True)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

ALGO_CHOICES = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3-256", "sha3-512", "blake2b", "blake2s",
]

TYPE_COLORS = {
    "MD5": "cyan",
    "SHA-1": "green",
    "SHA-256": "bright_green",
    "SHA-512": "bright_blue",
    "bcrypt": "yellow",
    "Argon2": "magenta",
    "NTLM": "red",
    "LM Hash": "bright_red",
    "Base64": "white",
}


def _color_for(name: str) -> str:
    return TYPE_COLORS.get(name, "bright_white")


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, "-V", "--version", prog_name="hashcrack")
def cli():
    """hashcrack — Hash identification and lookup tool for CTF and security research.

    \b
    Identify hash types, look up plaintexts, generate hashes, and more.
    """


# ─────────────────────────────────────────────
#  identify
# ─────────────────────────────────────────────
@cli.command("identify")
@click.argument("hash_string")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def identify(hash_string: str, output_json: bool):
    """Identify the type(s) of a given hash.

    \b
    Examples:
      hashcrack identify 5d41402abc4b2a76b9719d911017c592
      hashcrack identify '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
    """
    hash_string = hash_string.strip()
    matches = detect_hash(hash_string)

    if output_json:
        click.echo(json.dumps({"hash": hash_string, "matches": matches}, indent=2))
        return

    length = len(hash_string)
    console.print(Panel(
        f"[bold yellow]{hash_string}[/bold yellow]",
        title="[bold]Hash Input[/bold]",
        subtitle=f"Length: {length} chars",
        border_style="blue",
    ))

    if not matches:
        console.print("[red]No known hash type matched.[/red]")
        console.print(f"[dim]Hash length {length} — try checking for encoding issues.[/dim]")
        sys.exit(1)

    table = Table(
        title=f"[bold green]Possible Hash Types ({len(matches)} match{'es' if len(matches) != 1 else ''})[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold magenta",
    )
    table.add_column("Type", style="bold", min_width=14)
    table.add_column("Description", style="dim")
    table.add_column("Bits", justify="right", style="cyan")

    bits_map = {32: 128, 40: 160, 48: 192, 56: 224, 64: 256, 96: 384, 128: 512}

    for m in matches:
        bits = bits_map.get(m.get("length", 0), "—") if m.get("length") else "variable"
        color = _color_for(m["name"])
        table.add_row(
            f"[{color}]{m['name']}[/{color}]",
            m["description"],
            str(bits),
        )

    console.print(table)

    if len(matches) > 1:
        console.print(
            "[dim]Tip: Multiple types share the same length. Use [bold]hashcrack lookup[/bold] "
            "or context clues to narrow down.[/dim]"
        )


# ─────────────────────────────────────────────
#  lookup
# ─────────────────────────────────────────────
@cli.command("lookup")
@click.argument("hash_string")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Only print plaintext if found.")
def lookup(hash_string: str, output_json: bool, quiet: bool):
    """Look up plaintext for a hash via public databases.

    \b
    Searches multiple hash cracking APIs automatically.

    \b
    Examples:
      hashcrack lookup 5d41402abc4b2a76b9719d911017c592
      hashcrack lookup aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    """
    hash_string = hash_string.strip()

    if not quiet:
        matches = detect_hash(hash_string)
        types = ", ".join(m["name"] for m in matches) if matches else "Unknown"
        console.print(Panel(
            f"[bold yellow]{hash_string}[/bold yellow]\n[dim]Detected types: {types}[/dim]",
            title="[bold]Hash Lookup[/bold]",
            border_style="blue",
        ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        if not quiet:
            task = progress.add_task("Querying hash databases...", total=None)
        result = lookup_hash(hash_string)

    if output_json:
        click.echo(json.dumps({"hash": hash_string, **result}, indent=2))
        return

    if result["found"]:
        if quiet:
            click.echo(result["plaintext"])
        else:
            console.print(Panel(
                f"[bold green]CRACKED![/bold green]\n\n"
                f"Plaintext: [bold bright_green]{result['plaintext']}[/bold bright_green]\n"
                f"Source: [dim]{result['source']}[/dim]",
                title="[bold green]Result[/bold green]",
                border_style="green",
            ))
    else:
        if quiet:
            sys.exit(1)
        else:
            console.print(Panel(
                "[red]Not found in public databases.[/red]\n\n"
                "[dim]The hash may be:\n"
                "  • Using a strong algorithm (bcrypt, Argon2, scrypt)\n"
                "  • A custom or salted hash\n"
                "  • Not in any public rainbow table[/dim]",
                title="[bold red]Not Found[/bold red]",
                border_style="red",
            ))
            sys.exit(1)


# ─────────────────────────────────────────────
#  generate
# ─────────────────────────────────────────────
@cli.command("generate")
@click.argument("text")
@click.option(
    "--algo", "-a",
    multiple=True,
    type=click.Choice(ALGO_CHOICES, case_sensitive=False),
    help="Algorithm(s) to use. Repeat for multiple. Default: all common.",
)
@click.option("--all", "all_algos", is_flag=True, help="Generate all supported hashes.")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def generate(text: str, algo: tuple, all_algos: bool, output_json: bool):
    """Generate hash(es) for a given string.

    \b
    Examples:
      hashcrack generate "hello world"
      hashcrack generate "password" --algo md5 --algo sha256
      hashcrack generate "secret" --all
    """
    if all_algos or not algo:
        algorithms = ALGO_CHOICES
    else:
        algorithms = list(algo)

    results = {}
    for a in algorithms:
        h = generate_hash(text, a)
        if h:
            results[a] = h

    if output_json:
        click.echo(json.dumps({"input": text, "hashes": results}, indent=2))
        return

    table = Table(
        title=f"[bold]Hashes for:[/bold] [yellow]{text}[/yellow]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
    )
    table.add_column("Algorithm", style="bold cyan", min_width=12)
    table.add_column("Hash", style="white")

    for algo_name, hash_val in results.items():
        table.add_row(algo_name.upper(), hash_val)

    console.print(table)


# ─────────────────────────────────────────────
#  batch
# ─────────────────────────────────────────────
@cli.command("batch")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--lookup", "do_lookup", is_flag=True, help="Also attempt to look up plaintexts.")
@click.option("--output", "-o", type=click.Path(), help="Save results to a file (JSON).")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def batch(input_file: str, do_lookup: bool, output: Optional[str], output_json: bool):
    """Process multiple hashes from a file (one per line).

    \b
    Examples:
      hashcrack batch hashes.txt
      hashcrack batch hashes.txt --lookup
      hashcrack batch hashes.txt --lookup --output results.json
    """
    path = Path(input_file)
    lines = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]

    if not lines:
        console.print("[red]No hashes found in file.[/red]")
        sys.exit(1)

    console.print(Panel(
        f"Processing [bold]{len(lines)}[/bold] hash(es) from [cyan]{path.name}[/cyan]",
        title="[bold]Batch Mode[/bold]",
        border_style="blue",
    ))

    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Processing...", total=len(lines))

        for i, line in enumerate(lines, 1):
            progress.update(task, description=f"[{i}/{len(lines)}] {line[:32]}...")
            matches = detect_hash(line)
            entry = {
                "hash": line,
                "types": [m["name"] for m in matches],
                "found": False,
                "plaintext": None,
                "source": None,
            }
            if do_lookup and matches:
                result = lookup_hash(line)
                entry.update(result)
            all_results.append(entry)
            progress.advance(task)

    if output_json:
        click.echo(json.dumps(all_results, indent=2))
    else:
        table = Table(
            title=f"[bold]Batch Results — {len(all_results)} hashes[/bold]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold magenta",
        )
        table.add_column("Hash", style="dim", max_width=40)
        table.add_column("Detected Types", style="cyan")
        if do_lookup:
            table.add_column("Plaintext", style="bold green")
            table.add_column("Source", style="dim")

        for entry in all_results:
            short_hash = entry["hash"][:36] + "..." if len(entry["hash"]) > 36 else entry["hash"]
            types_str = ", ".join(entry["types"]) if entry["types"] else "[red]Unknown[/red]"
            if do_lookup:
                plaintext = f"[green]{entry['plaintext']}[/green]" if entry["found"] else "[red]Not found[/red]"
                source = entry["source"] or ""
                table.add_row(short_hash, types_str, plaintext, source)
            else:
                table.add_row(short_hash, types_str)

        console.print(table)

    if output:
        Path(output).write_text(json.dumps(all_results, indent=2))
        console.print(f"\n[dim]Results saved to [cyan]{output}[/cyan][/dim]")

    if do_lookup:
        found_count = sum(1 for r in all_results if r["found"])
        console.print(
            f"\n[bold]Summary:[/bold] {found_count}/{len(all_results)} hashes cracked "
            f"[dim]({100*found_count//len(all_results) if all_results else 0}%)[/dim]"
        )


# ─────────────────────────────────────────────
#  verify
# ─────────────────────────────────────────────
@cli.command("verify")
@click.argument("hash_string")
@click.argument("plaintext")
@click.option(
    "--algo", "-a",
    type=click.Choice(ALGO_CHOICES, case_sensitive=False),
    help="Force a specific algorithm.",
)
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def verify(hash_string: str, plaintext: str, algo: Optional[str], output_json: bool):
    """Verify that a plaintext matches a hash.

    \b
    Examples:
      hashcrack verify 5d41402abc4b2a76b9719d911017c592 "hello"
      hashcrack verify <sha256_hash> "password" --algo sha256
    """
    hash_string = hash_string.strip()

    if algo:
        algorithms_to_try = [algo]
    else:
        matches = detect_hash(hash_string)
        if not matches:
            err_console.print("[red]Cannot detect hash type. Use --algo to specify.[/red]")
            sys.exit(1)
        algorithms_to_try = [m["name"].lower().replace("-", "").replace(" ", "")
                              for m in matches if m.get("length")]

    verified = False
    matched_algo = None

    for a in algorithms_to_try:
        clean_algo = a.lower().replace("-", "").replace("_", "").replace(" ", "")
        if verify_hash(hash_string, plaintext, clean_algo):
            verified = True
            matched_algo = a
            break

    if output_json:
        click.echo(json.dumps({
            "hash": hash_string,
            "plaintext": plaintext,
            "verified": verified,
            "algorithm": matched_algo,
        }, indent=2))
        return

    if verified:
        console.print(Panel(
            f"[bold green]MATCH![/bold green]\n\n"
            f"Hash:      [dim]{hash_string}[/dim]\n"
            f"Plaintext: [bold green]{plaintext}[/bold green]\n"
            f"Algorithm: [cyan]{matched_algo}[/cyan]",
            title="[bold green]Verification[/bold green]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]NO MATCH[/bold red]\n\n"
            f"Hash:      [dim]{hash_string}[/dim]\n"
            f"Plaintext: [yellow]{plaintext}[/yellow]\n"
            f"Tried:     [dim]{', '.join(algorithms_to_try)}[/dim]",
            title="[bold red]Verification Failed[/bold red]",
            border_style="red",
        ))
        sys.exit(1)


# ─────────────────────────────────────────────
#  info
# ─────────────────────────────────────────────
@cli.command("info")
@click.argument("hash_type", required=False)
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def info(hash_type: Optional[str], output_json: bool):
    """Show information about a hash algorithm, or list all supported types.

    \b
    Examples:
      hashcrack info           # list all supported hash types
      hashcrack info md5       # details on MD5
      hashcrack info sha256
    """
    if hash_type:
        target = hash_type.upper().replace("_", "-").replace(" ", "-")
        matches = [p for p in HASH_PATTERNS if p["name"].upper() == target]

        if not matches:
            # Try fuzzy
            matches = [p for p in HASH_PATTERNS if target in p["name"].upper()]

        if not matches:
            err_console.print(f"[red]Unknown hash type: {hash_type}[/red]")
            err_console.print("[dim]Run [bold]hashcrack info[/bold] to list all types.[/dim]")
            sys.exit(1)

        m = matches[0]
        if output_json:
            click.echo(json.dumps(m, indent=2))
            return

        bits_map = {32: 128, 40: 160, 48: 192, 56: 224, 64: 256, 96: 384, 128: 512}
        bits = bits_map.get(m.get("length", 0), "variable")
        color = _color_for(m["name"])

        console.print(Panel(
            f"[bold {color}]{m['name']}[/bold {color}]\n\n"
            f"[dim]Description:[/dim] {m['description']}\n"
            f"[dim]Hex length:[/dim]  {m.get('length', 'variable')}\n"
            f"[dim]Bits:[/dim]        {bits}\n"
            f"[dim]Pattern:[/dim]     [dim]{m['regex']}[/dim]\n\n"
            f"[dim]Example:[/dim]\n[yellow]{m['example']}[/yellow]",
            title=f"[bold]Hash Info — {m['name']}[/bold]",
            border_style=color,
        ))
    else:
        if output_json:
            click.echo(json.dumps(HASH_PATTERNS, indent=2))
            return

        table = Table(
            title="[bold]Supported Hash Types[/bold]",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold magenta",
        )
        table.add_column("Type", style="bold", min_width=14)
        table.add_column("Bits", justify="right", style="cyan")
        table.add_column("Hex Length", justify="right", style="dim")
        table.add_column("Description", style="white")

        bits_map = {32: 128, 40: 160, 48: 192, 56: 224, 64: 256, 96: 384, 128: 512}

        for p in HASH_PATTERNS:
            bits = bits_map.get(p.get("length", 0), "var")
            color = _color_for(p["name"])
            table.add_row(
                f"[{color}]{p['name']}[/{color}]",
                str(bits),
                str(p.get("length", "—")),
                p["description"],
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(HASH_PATTERNS)} hash types. Run [bold]hashcrack info <type>[/bold] for details.[/dim]")


# ─────────────────────────────────────────────
#  analyze
# ─────────────────────────────────────────────
@cli.command("analyze")
@click.argument("hash_string")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def analyze(hash_string: str, output_json: bool):
    """Deep analysis of a hash: type detection + lookup + entropy.

    \b
    Combines identify, lookup, and statistical analysis in one command.

    \b
    Examples:
      hashcrack analyze 5d41402abc4b2a76b9719d911017c592
    """
    import math

    hash_string = hash_string.strip()
    matches = detect_hash(hash_string)

    # Entropy calculation
    freq = {}
    for ch in hash_string.lower():
        freq[ch] = freq.get(ch, 0) + 1
    length = len(hash_string)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    # Character distribution
    hex_chars = sum(1 for c in hash_string if c in "0123456789abcdefABCDEF")
    is_pure_hex = hex_chars == length

    result = {
        "hash": hash_string,
        "length": length,
        "entropy": round(entropy, 4),
        "is_pure_hex": is_pure_hex,
        "detected_types": [m["name"] for m in matches],
        "lookup": None,
    }

    console.print(Panel(
        f"[bold yellow]{hash_string}[/bold yellow]",
        title="[bold]Deep Hash Analysis[/bold]",
        border_style="magenta",
    ))

    # Stats table
    stats = Table(box=box.SIMPLE, show_header=False)
    stats.add_column("Property", style="dim")
    stats.add_column("Value", style="bold")

    stats.add_row("Length", f"{length} characters")
    stats.add_row("Entropy", f"{entropy:.2f} bits/char")
    stats.add_row("Pure hex", "Yes" if is_pure_hex else "No")
    stats.add_row("Charset", _describe_charset(hash_string))

    console.print(stats)

    if matches:
        console.print(f"\n[bold green]Detected Types:[/bold green]")
        for m in matches:
            color = _color_for(m["name"])
            console.print(f"  [{color}]●[/{color}] [bold]{m['name']}[/bold] — {m['description']}")
    else:
        console.print("[yellow]No known hash type matched.[/yellow]")

    # Attempt lookup for hex hashes
    if is_pure_hex and length in (32, 40, 64, 128):
        console.print("\n[dim]Attempting lookup in public databases...[/dim]")
        lookup_result = lookup_hash(hash_string)
        result["lookup"] = lookup_result
        if lookup_result["found"]:
            console.print(Panel(
                f"[bold green]CRACKED![/bold green]  Plaintext: [bright_green]{lookup_result['plaintext']}[/bright_green]\n"
                f"[dim]Source: {lookup_result['source']}[/dim]",
                border_style="green",
            ))
        else:
            console.print("[dim]Not found in public databases.[/dim]")

    if output_json:
        click.echo(json.dumps(result, indent=2))


def _describe_charset(s: str) -> str:
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_special = any(not c.isalnum() for c in s)
    parts = []
    if has_lower:
        parts.append("lowercase")
    if has_upper:
        parts.append("uppercase")
    if has_digit:
        parts.append("digits")
    if has_special:
        parts.append("special")
    return ", ".join(parts) if parts else "unknown"


# ─────────────────────────────────────────────
#  wordlist
# ─────────────────────────────────────────────
@cli.command("wordlist")
@click.argument("wordlist_file", type=click.Path(exists=True))
@click.argument("hash_string")
@click.option(
    "--algo", "-a",
    type=click.Choice(ALGO_CHOICES, case_sensitive=False),
    default="md5",
    show_default=True,
    help="Hash algorithm to use.",
)
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
def wordlist(wordlist_file: str, hash_string: str, algo: str, output_json: bool):
    """Crack a hash using a local wordlist file.

    \b
    Hashes each line of the wordlist and compares against the target.

    \b
    Examples:
      hashcrack wordlist rockyou.txt 5d41402abc4b2a76b9719d911017c592
      hashcrack wordlist passwords.txt <sha256_hash> --algo sha256
    """
    hash_string = hash_string.strip().lower()
    path = Path(wordlist_file)

    total_lines = sum(1 for _ in path.open("r", errors="ignore"))

    console.print(Panel(
        f"Target: [bold yellow]{hash_string}[/bold yellow]\n"
        f"Algorithm: [cyan]{algo.upper()}[/cyan]\n"
        f"Wordlist: [dim]{path.name}[/dim] ([bold]{total_lines:,}[/bold] words)",
        title="[bold]Wordlist Attack[/bold]",
        border_style="blue",
    ))

    found = False
    plaintext = None
    tried = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Cracking...", total=total_lines)

        with path.open("r", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\n\r")
                computed = generate_hash(word, algo)
                tried += 1
                progress.advance(task)

                if computed and computed.lower() == hash_string:
                    found = True
                    plaintext = word
                    break

    if output_json:
        click.echo(json.dumps({
            "hash": hash_string,
            "algorithm": algo,
            "found": found,
            "plaintext": plaintext,
            "tried": tried,
        }, indent=2))
        return

    if found:
        console.print(Panel(
            f"[bold green]CRACKED![/bold green]\n\n"
            f"Plaintext: [bold bright_green]{plaintext}[/bold bright_green]\n"
            f"Tried: [dim]{tried:,} words[/dim]",
            title="[bold green]Success[/bold green]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[red]Not found in wordlist.[/red]\n[dim]Tried {tried:,} words.[/dim]",
            title="[bold red]Not Found[/bold red]",
            border_style="red",
        ))
        sys.exit(1)
