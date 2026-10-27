# Bridge-forwarding proof of concept

This branch adds native nftables bridge-forwarding enforcement alongside the
existing inet INPUT/OUTPUT backend. It uses the same MultiNetworkPolicy API,
`policy-for` NAD selection, and interface names from Multus network-status.

## Topology

The connectivity interface must itself be a Linux bridge port, for example:

```text
Customer network -- net1 -- Linux bridge -- TAP -- workload
```

`net1` remains the interface reported by Multus. It may have no IP addresses;
the workload can obtain its address from the customer's DHCP server.

Ingress policy matches `iifname net1` at the bridge FORWARD hook. Egress policy
matches `oifname net1`. The controller does not need to identify the bridge,
TAP, workload type, or binding name. It also does not configure the topology or
the bridge FDB: that remains the binding/network setup's responsibility.

## Enforcement

Every selected policy is rendered in two independent nftables tables:

- `inet multi_networkpolicy`: existing local INPUT/OUTPUT behavior.
- `bridge multi_networkpolicy`: IP traffic forwarded through selected ports.

The bridge table has `forward-ingress` and `forward-egress` base chains, both
using the `forward` hook, at priorities 0 and 10 respectively. Their default
policy is accept; only selected network interfaces dispatch to policy chains.
An accept in the ingress base chain does not skip the egress base chain when
both ports are policy-managed.

The bridge backend uses separate per-policy ingress and egress chains. Sharing
the same per-policy chain, as the existing local-stack backend does, would let
one direction's permissions match the other direction on transit packets.

Rules use the kernel's `meta protocol` to classify IPv4/IPv6, including the
single-tagged VLAN case covered by the tests. Non-IP traffic such as ARP is not
sent through the IP policy chains. The bridge backend uses native bridge
connection tracking for established/related return traffic. The local-stack
reverse-IP exemption is not applied to transit packets.

Policy selection, peer address sets, port rules, common-rule configuration and
cleanup are driven by the existing controller. There is no rule-mirroring agent
or nftables notification listener in the binding.

## Requirements and scope

- Nodes need nftables bridge-family and native bridge conntrack support
  (`CONFIG_NF_TABLES_BRIDGE` and `CONFIG_NF_CONNTRACK_BRIDGE`). The PoC attempts to
  install both backends; lack of bridge support is reported as an error.
- `br_netfilter` / `bridge-nf-call-iptables` is not required for the native bridge
  backend. The existing inet backend remains for local endpoints.
- A direct TC-to-TAP redirect still bypasses these bridge hooks. That is not the
  topology implemented by this PoC.
- DHCP and IPv6 discovery are IP traffic. Policies/common rules must permit the
  configuration protocol required by the workload. The bridge does not provide
  a DHCP service.
- An unnumbered attachment can be a policy target, but IP-based peer selectors
  still need the peers' addresses in network-status.
- Policy cleanup/rendering retains the existing reconciliation model. This PoC
  does not make cross-family updates a single atomic transaction.
- Native bridge support does not imply transparent support for every custom
  inet expression or all encapsulation/offload combinations. Tests cover the
  common IP policy paths and a single 802.1Q VLAN, not arbitrary QinQ trunks.

## Tests

The existing inet golden files remain unchanged and are checked independently.
The new `Bridge forwarding datapath` tests use real network namespaces and a
real TAP pair connected by a test-only Go packet pump. They exercise generated
policies with actual TCP packets, including:

- An unnumbered, unrenamed network port.
- Independent IPv4/IPv6 ingress/egress denial and stateful return traffic.
- Allow-union behavior, policy deletion and changed selection.
- Peer selector set regeneration.
- Both bridge ports being policy-managed.
- Ordinary local endpoint enforcement alongside a bridge.
- Single-tagged VLAN IP traffic.

As with the existing nftables integration tests, these tests need privileges to
create network namespaces and install nftables rules, plus `ip`, `bridge`, `nft`,
`sysctl`, and `/dev/net/tun`. They do not require a Kubernetes API server.
