import dns.resolver
import sys

# Function to get DNS response from a specified DNS server
def get_dns_record(domain, dns_server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        answer = resolver.resolve(domain, 'A')
        ip_address = answer[0].address
        ttl = answer.rrset.ttl
        return ip_address, ttl
    except Exception as e:
        print(f"Failed to resolve {domain} on {dns_server}: {e}")
        return None, None

# Function to compare DNS responses
def compare_dns_records(domain, local_dns, trusted_dns):
    local_ip, local_ttl = get_dns_record(domain, local_dns)
    trusted_ip, trusted_ttl = get_dns_record(domain, trusted_dns)

    if not local_ip or not trusted_ip:
        print("DNS resolution failed. Exiting...")
        return

    print(f"Local DNS ({local_dns}) - IP: {local_ip}, TTL: {local_ttl}")
    print(f"Trusted DNS ({trusted_dns}) - IP: {trusted_ip}, TTL: {trusted_ttl}")

    if local_ip != trusted_ip:
        print("ALERT: DNS Cache Poisoning suspected! IP addresses do not match.")
    else:
        print("No DNS Cache Poisoning detected.")

# Main function
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python dns_cache_poisoning.py <domain> <local_dns> <trusted_dns>")
        sys.exit(1)

    domain = sys.argv[1]
    local_dns = sys.argv[2]
    trusted_dns = sys.argv[3]

    compare_dns_records(domain, local_dns, trusted_dns)
