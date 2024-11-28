import dns.resolver
import dns.dnssec
import dns.message
import dns.query
import dns.rdatatype
import logging

# Set up logging to store DNS checks
logging.basicConfig(filename='dnssec_poisoning_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to verify DNSSEC
def verify_dnssec(domain, dns_server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]

    try:
        # Perform DNS query for the A record with DNSSEC
        query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(query, dns_server)

        # Check if DNSSEC information is available
        if response.rcode() != dns.rcode.NOERROR:
            logging.error(f"DNS query failed for {domain} on {dns_server}")
            return False

        if not response.flags & dns.flags.AD:
            logging.warning(f"DNSSEC validation failed for {domain} on {dns_server}")
            return False

        # Get the DNSKEY record
        query_dnskey = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response_dnskey = dns.query.udp(query_dnskey, dns_server)

        # Extract the DNSKEY and RRSIG records
        dnskey_rrset = response_dnskey.find_rrset(response_dnskey.answer, dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        rrsig = response_dnskey.find_rrset(response_dnskey.answer, dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)

        # Verify DNSSEC
        dns.dnssec.validate(dnskey_rrset, rrsig, {dns.name.from_text(domain): dnskey_rrset})

        logging.info(f"DNSSEC validation passed for {domain} on {dns_server}")
        return True

    except dns.dnssec.ValidationFailure:
        logging.error(f"DNSSEC validation failed for {domain} on {dns_server}")
        return False
    except Exception as e:
        logging.error(f"Failed to resolve {domain} on {dns_server}: {e}")
        return False

# Main function to run the DNSSEC check
if __name__ == "__main__":
    domain = "www.gogle.com"
    dns_server = "8.8.8.8"

    logging.info("Starting DNSSEC validation...")
    if verify_dnssec(domain, dns_server):
        logging.info(f"No DNS Cache Poisoning detected for {domain}.")
    else:
        logging.warning(f"Possible DNS Cache Poisoning detected for {domain}.")
