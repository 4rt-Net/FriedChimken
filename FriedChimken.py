import requests
from colorama import Fore, Style, init
import argparse

# Initialize colorama
init(autoreset=True)

# List of security headers to check with descriptions
security_headers = {
    "Strict-Transport-Security": (
        "Enforces HTTPS and protects against protocol downgrade attacks."
    ),
    "Content-Security-Policy": (
        "Helps prevent XSS attacks by specifying allowed sources of content."
    ),
    "X-Frame-Options": (
        "Mitigates clickjacking attacks by preventing the site from being embedded in frames."
    ),
    "X-Content-Type-Options": (
        "Prevents browsers from interpreting files as a different MIME type."
    ),
    "Referrer-Policy": (
        "Controls what information is sent in the Referer header when navigating to another site."
    ),
    "Permissions-Policy": (
        "Restricts the use of browser features like camera, microphone, and geolocation."
    ),
}

def check_security_headers(url, output_file):
    try:
        # Send GET request to the URL
        response = requests.get(url, timeout=10)
        headers = response.headers

        result = f"\n{Style.BRIGHT}Checking security headers for {Fore.BLUE}{url}{Style.RESET_ALL}:\n\n"
        for header, description in security_headers.items():
            if header in headers:
                result += f"{Fore.GREEN}[+] {header}: {headers[header]}\n"
            else:
                result += (
                    f"{Fore.RED}[-] {header} is missing\n"
                    f"    {Fore.YELLOW}Implication: {description}\n"
                )

        result += f"\n{Style.BRIGHT}{Fore.CYAN}Scan complete.{Style.RESET_ALL}\n"

        print(result)
        with open(output_file, "a") as f:
            f.write(result)
    except requests.exceptions.RequestException as e:
        error_message = f"{Fore.RED}Error: {e}\n"
        print(error_message)
        with open(output_file, "a") as f:
            f.write(error_message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check security headers for URLs.")
    parser.add_argument("-u", "--url", help="Single URL to check.")
    parser.add_argument("-f", "--file", help="File containing a list of URLs to check.")
    parser.add_argument("-o", "--output", default="output.txt", help="Output file to save results.")

    args = parser.parse_args()

    if not args.url and not args.file:
        print(f"{Fore.RED}Error: Please provide a URL (-u) or a file (-f) containing URLs to check.{Style.RESET_ALL}")
        exit(1)

    if args.url:
        check_security_headers(args.url, args.output)

    if args.file:
        try:
            with open(args.file, "r") as file:
                urls = file.readlines()
                for url in urls:
                    url = url.strip()
                    if url:
                        check_security_headers(url, args.output)
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File {args.file} not found.{Style.RESET_ALL}")
