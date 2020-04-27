#!/usr/bin/env python

import os

from moulinette.utils.filesystem import read_file

from yunohost.utils.network import dig
from yunohost.diagnosis import Diagnoser
from yunohost.domain import domain_list, _build_dns_conf, _get_maindomain


class DNSRecordsDiagnoser(Diagnoser):

    id_ = os.path.splitext(os.path.basename(__file__))[0].split("-")[1]
    cache_duration = 600
    dependencies = ["ip"]

    def run(self):

        resolvers = read_file("/etc/resolv.dnsmasq.conf").split("\n")
        ipv4_resolvers = [r.split(" ")[1] for r in resolvers if r.startswith("nameserver") and ":" not in r]
        # FIXME some day ... handle ipv4-only and ipv6-only servers. For now we assume we have at least ipv4
        assert ipv4_resolvers != [], "Uhoh, need at least one IPv4 DNS resolver ..."

        self.resolver = ipv4_resolvers[0]
        main_domain = _get_maindomain()

        all_domains = domain_list()["domains"]
        for domain in all_domains:
            self.logger_debug("Diagnosing DNS conf for %s" % domain)
            is_subdomain = domain.split(".",1)[1] in all_domains
            for report in self.check_domain(domain, domain == main_domain, is_subdomain=is_subdomain):
                yield report

        # FIXME : somewhere, should implement a check for reverse DNS ...

        # FIXME / TODO : somewhere, could also implement a check for domain expiring soon

    def check_domain(self, domain, is_main_domain, is_subdomain):

        expected_configuration = _build_dns_conf(domain, include_empty_AAAA_if_no_ipv6=True)

        categories = ["basic", "mail", "xmpp", "extra"]
        # For subdomains, we only diagnosis A and AAAA records
        if is_subdomain:
            categories = ["basic"]

        for category in categories:

            records = expected_configuration[category]
            discrepancies = []
            results = {}

            for r in records:
                id_ = r["type"] + ":" + r["name"]
                r["current"] = self.get_current_record(domain, r["name"], r["type"])
                if r["value"] == "@":
                    r["value"] = domain + "."

                if self.current_record_match_expected(r):
                    results[id_] = "OK"
                else:
                    if r["current"] is None:
                        results[id_] = "MISSING"
                        discrepancies.append(("diagnosis_dns_missing_record", r))
                    else:
                        results[id_] = "WRONG"
                        discrepancies.append(("diagnosis_dns_discrepancy", r))


            def its_important():
                # Every mail DNS records are important for main domain
                # For other domain, we only report it as a warning for now...
                if is_main_domain and category == "mail":
                    return True
                elif category == "basic":
                    # A bad or missing A record is critical ...
                    # And so is a wrong AAAA record
                    # (However, a missing AAAA record is acceptable)
                    if results["A:@"] != "OK" or results["AAAA:@"] == "WRONG":
                        return True

                return False

            if discrepancies:
                status = "ERROR" if its_important() else "WARNING"
                summary = "diagnosis_dns_bad_conf"
            else:
                status = "SUCCESS"
                summary = "diagnosis_dns_good_conf"

            output = dict(meta={"domain": domain, "category": category},
                          data=results,
                          status=status,
                          summary=summary)

            if discrepancies:
                output["details"] = ["diagnosis_dns_point_to_doc"] + discrepancies

            yield output

    def get_current_record(self, domain, name, type_):

        query = "%s.%s" % (name, domain) if name != "@" else domain
        success, answers = dig(query, type_, resolvers="force_external")

        if success != "ok":
            return None
        else:
            return answers[0] if len(answers) == 1 else answers

    def current_record_match_expected(self, r):
        if r["value"] is not None and r["current"] is None:
            return False
        if r["value"] is None and r["current"] is not None:
            return False
        elif isinstance(r["current"], list):
            return False

        if r["type"] == "TXT":
            # Split expected/current
            #  from  "v=DKIM1; k=rsa; p=hugekey;"
            #  to a set like {'v=DKIM1', 'k=rsa', 'p=...'}
            expected = set(r["value"].strip(';" ').replace(";", " ").split())
            current = set(r["current"].strip(';" ').replace(";", " ").split())

            # For SPF, ignore parts starting by ip4: or ip6:
            if r["name"] == "@":
                current = {part for part in current if not part.startswith("ip4:") and not part.startswith("ip6:")}
            return expected == current
        elif r["type"] ==  "MX":
            # For MX, we want to ignore the priority
            expected = r["value"].split()[-1]
            current = r["current"].split()[-1]
            return expected == current
        else:
            return r["current"] == r["value"]


def main(args, env, loggers):
    return DNSRecordsDiagnoser(args, env, loggers).diagnose()
