import fire
import os
os.environ["PAGER"] = "cat"
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from phish import urlDissection, finalVerdict

console = Console()

ASCII = (
    ".______    __    __   __       _______. __    __\n"
    "|   _  \\  |  |  |  | |  |     /       ||  |  |  |\n"
    "|  |_)  | |  |__|  | |  |    |   (----`|  |__|  |\n"
    "|   ___/  |   __   | |  |     \\   \\    |   __   |\n"
    "|  |      |  |  |  | |  | .----)   |   |  |  |  |\n"
    "| _|      |__|  |__| |__| |_______/    |__|  |__|"
)

_LEVEL_STYLE = {
    "High Risk":  ("bold red",    "bold red"),
    "Suspicious": ("bold yellow", "bold yellow"),
    "Safe":       ("bold green",  "bold green"),
}


class Phish:
    """Phishing URL scanner"""

    def scan(self, url: str):
        """Scan a URL for phishing indicators.
        Args:
            url: The URL to scan.
        """
        console.print(Panel(
            Text(ASCII, style="yellow"),
            title="[bold #f5e960]PHISH[/bold #f5e960]",
            subtitle="[dim]v1.0.0  |  Jawad Hossain  |  github.com/jwd06[/dim]",
            border_style="bright_magenta" ,
            padding=(1, 2),
        ))

        components = urlDissection(url)

        with console.status("[bold cyan]Scanning URL...[/bold cyan]", spinner="dots"):
            result = finalVerdict(url, components)

        border_style, score_style = _LEVEL_STYLE[result["level"]]
        title = f"[{border_style}]  {result['level'].upper()}  [/{border_style}]"

        lines = []
        lines.append(f"[{score_style}]Score: {result['score']:.2f}[/{score_style}]")
        lines.append("")

        triggers = result["triggers"]
        if triggers:
            lines.append("[bold]Triggers:[/bold]")
            for t in triggers:
                lines.append(f"  [dim]•[/dim] {t}")
        else:
            lines.append("[dim]No indicators detected.[/dim]")

        lines.append("")
        age = result["age_days"]
        if age is not None:
            lines.append(f"[dim]Domain Age:[/dim] {age} days  ({age / 365.25:.2f} years)")
        else:
            lines.append("[dim]Domain Age:[/dim] unavailable")

        console.print(Panel(
            "\n".join(lines),
            title=title,
            border_style=border_style,
            padding=(1, 2),
        ))


def main():
    fire.Fire(Phish)


if __name__ == "__main__":
    main()
