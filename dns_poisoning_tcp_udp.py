import dns.resolver
import logging

# Set up logging to store DNS checks
logging.basicConfig(filename='dns_poisoning_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to get DNS response using a specified protocol (UDP or TCP)
def get_dns_record(domain, dns_server, use_tcp=False):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        answer = resolver.resolve(domain, 'A', tcp=use_tcp)
        ip_address = answer[0].address
        ttl = answer.rrset.ttl
        protocol = 'TCP' if use_tcp else 'UDP'
        return ip_address, ttl, protocol
    except Exception as e:
        logging.error(f"Failed to resolve {domain} on {dns_server} using {'TCP' if use_tcp else 'UDP'}: {e}")
        return None, None, None

# Function to compare DNS responses from UDP and TCP
def compare_dns_records(domain, dns_server):
    udp_ip, udp_ttl, udp_protocol = get_dns_record(domain, dns_server, use_tcp=False)
    tcp_ip, tcp_ttl, tcp_protocol = get_dns_record(domain, dns_server, use_tcp=True)

    if not udp_ip or not tcp_ip:
        logging.error("DNS resolution failed.")
        return

    logging.info(f"{udp_protocol} - IP: {udp_ip}, TTL: {udp_ttl}")
    logging.info(f"{tcp_protocol} - IP: {tcp_ip}, TTL: {tcp_ttl}")

    if udp_ip != tcp_ip:
        logging.warning(f"ALERT: DNS Cache Poisoning suspected! IP addresses do not match between UDP and TCP for {domain}.")
    elif udp_ttl != tcp_ttl:
        logging.warning(f"ALERT: DNS Cache Poisoning suspected! TTL values do not match between UDP and TCP for {domain}.")
    else:
        logging.info(f"No DNS Cache Poisoning detected for {domain}.")

# Main function to run the check
if __name__ == "__main__":
    domain = "www.spotify.com"
    dns_server = "8.8.8.8"

    logging.info("Starting DNS Cache Poisoning detection...")
    compare_dns_records(domain, dns_server)
