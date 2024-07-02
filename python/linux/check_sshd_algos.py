import asyncio
import sys
import os
import re
import argparse

# Check prerequisites
if sys.version_info < (3,6):
    print("This program requires Python 3.6 or higher")
    exit()

if os.name != "posix":
    print(f"This program does not support {os.name}")
    exit()


# This list of supported algorithms is listed in docs
# https://support.quest.com/technical-documents/foglight/7.1.0/security-and-compliance-guide/8#TOPIC-2149356
supported_algos = {
    "kexalgorithms" : {"diffie-hellman-group14-sha1","diffie-hellman-group-exchange-sha256","diffie-hellman-group-exchange-sha1","diffie-hellman-group1-sha1"},
    "hostkeyalgorithms" : {"ssh-rsa", "ssh-dss"},
    "ciphers" : {"aes128-ctr","aes192-ctr","aes256-ctr","aes128-cbc","aes192-cbc","aes256-cbc","3des-ctr","3des-cbc","blowfish-ctr","blowfish-cbc"},
    "macs" : {"hmac-sha1","hmac-sha2-256","hmac-sha2-512","hmac-sha1-96","hmac-md5-96","hmac-md5"},
}

# Basic input validation
def is_valid_hostname_or_ip(address):
    if len(address) > 253:
        return False

    # Define the regular expression for a valid hostname
    hostname_regex = re.compile(
        r'^(?=.{1,253}$)'  # Entire hostname length must be between 1 and 253 characters
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.?)*$'  # Labels between dots must follow the rules
    )

    # Define the regular expression for a valid IPv4 address
    ipv4_regex = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'  # First three octets
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'  # Fourth octet
    )

    return bool(hostname_regex.match(address) or ipv4_regex.match(address))

# Run shell command with a short async timeout
async def shrun(executable, *parameters, seconds):
    print(f"Running {executable} with a timeout of {seconds} seconds")
    proc = await asyncio.create_subprocess_exec(
        executable, *parameters, 
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    await timeout(proc, seconds)
    _, stderr = await proc.communicate()

    print(f'[{executable!r} exited with {proc.returncode}]')

    if stderr:
        return stderr.decode()
    return None

# This is the async implementation of the timeout
async def timeout(proc: asyncio.subprocess.Process, n: int):
    """Times out the process after n seconds"""
    await asyncio.sleep(n)
    if not proc.returncode:
        proc.kill()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate sshd algorithms")
    # Define command-line arguments
    parser.add_argument('-H', '--hostname', type=str, help='Hostname or IP address', default="localhost")
    parser.add_argument('-t', '--timeout', type=int, help='Timeout seconds', default=2)
    args = parser.parse_args()

    # Validate hostname
    if is_valid_hostname_or_ip(args.hostname):
        host = args.hostname
    else:
        print(f"Invalid host {args.hostname}")
        exit()
    
    seconds = args.timeout
    
    out = asyncio.run(shrun('ssh', '-vvv', host, seconds=seconds))
    if "peer server KEXINIT proposal" not in out:
        print("Key Exchange proposals for sshd were not found.")
        exit()
    start = out.index("peer server KEXINIT proposal")
    relevant_fields = {
        "KEX algorithms":"kexalgorithms",
        "host key algorithms":"hostkeyalgorithms",
        "ciphers ctos": "ciphers",
        "ciphers stoc": "ciphers",
        "MACs ctos": "macs",
        "MACs stoc": "macs"
    }

    print("\n\n", "="*10,f"Key Exchange proposals overlap for {host}:","="*10)
    
    # split lines an iterate over output
    for line in out[start:].split("\n"):
        # check each line for relevant fields
        for field in relevant_fields:
            if field not in line:
                continue
            items = {i.strip() for i in line.split(": ")[2].split(",")}
            overlap = supported_algos[relevant_fields[field]] & items
            if len(overlap):
                print(f"{relevant_fields[field]}: {overlap}")
            else:
                print(f"{relevant_fields[field]}: NO OVERLAP!!")