import ipaddress

from typing import Dict
from typing import List
from typing import Union

from types import NoneType

from ansible.plugins.lookup import LookupBase  # type: ignore[import]
from ansible.errors import AnsibleLookupError  # type: ignore[import]


def subnets_from_wild(address: str, mask: str) -> List[ipaddress.IPv4Network]:
    """Build a list of subnets given an address and wildcard mask"""
    mask_int = int.from_bytes((ipaddress.IPv4Address(mask).packed), "big")
    address_int = int.from_bytes(ipaddress.IPv4Address(address).packed, "big")
    lower = ipaddress.IPv4Address((2 ** 32 - 1 - mask_int) & address_int)
    upper = ipaddress.IPv4Address(mask_int | address_int)
    subnet_range = list(ipaddress.summarize_address_range(lower, upper))
    return subnet_range


def check_addr_tuple(net_to_match: ipaddress.IPv4Network, addr_tuple: Dict) -> bool:
    """Check if the source or destination matches"""
    if "any" in addr_tuple and addr_tuple["any"] is True:
        return True
    else:
        match_address = addr_tuple.get("address") or addr_tuple["host"]
        match_wild_bits = addr_tuple.get("wildcard_bits") or "0.0.0.0"
        match_nets = subnets_from_wild(match_address, match_wild_bits)
        return any(net_to_match.subnet_of(match_net) for match_net in match_nets)


class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):
        gathered = kwargs.get("gathered")
        grant = kwargs.get("grant")
        if grant not in ["permit", "deny"]:
            raise AnsibleLookupError("Grant must be permit or deny")

        if "source" in kwargs:
            try:
                source = ipaddress.ip_network(kwargs.get("source"))
            except ValueError:
                raise AnsibleLookupError("Invalid source")
        else:
            source = None

        if "destination" in kwargs:
            try:
                destination = ipaddress.ip_network(kwargs.get("destination"))
            except ValueError:
                raise AnsibleLookupError("Invalid destination")
        else:
            destination = None

        if not source and not destination:
            raise AnsibleLookupError("Source and/or destination must be provided")

        afi_type = None
        if isinstance(source, (ipaddress.IPv4Network, NoneType)) and isinstance(
            destination, (ipaddress.IPv4Network, NoneType)
        ):
            afi_type = "ipv4"
        elif isinstance(source, (ipaddress.IPv6Network, NoneType)) and isinstance(
            destination, (ipaddress.IPv6Network, NoneType)
        ):
            afi_type = "ipv6"
        else:
            raise AnsibleLookupError("Mismatch address types")

        found = []
        for afi in gathered:
            if afi["afi"] == afi_type:
                for acl in afi["acls"]:
                    name = acl["name"]
                    for ace in acl.get("aces", []):
                        source_matched = False
                        destination_matched = False
                        if "grant" in ace and ace["grant"] == grant:
                            if source:
                                source_matched = check_addr_tuple(
                                    net_to_match=source, addr_tuple=ace["source"]
                                )
                            if destination:
                                if "destination" in ace:
                                    destination_matched = check_addr_tuple(
                                        net_to_match=destination,
                                        addr_tuple=ace["destination"],
                                    )
                                else:
                                    destination_matched = True

                            if destination is None and source_matched:
                                found.append(name)
                            elif source is None and destination_matched:
                                found.append(name)
                            elif source_matched and destination_matched:
                                found.append(name)

        return sorted(list(set(found)), key=lambda x: str(x))
