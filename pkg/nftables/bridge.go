package nftables

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/knftables"

	"github.com/k8snetworkplumbingwg/multi-network-policy-nftables/pkg/datastore"
	"github.com/k8snetworkplumbingwg/multi-network-policy-nftables/pkg/utils"
)

const (
	forwardIngressChain = "forward-ingress"
	forwardEgressChain  = "forward-egress"
)

// enforceBridgePolicy protects IP traffic forwarded through the interfaces
// reported by Multus. Registering the hooks does not require a bridge to exist,
// and does not require knowledge of the workload behind a bridge port.
func (n *NFTables) enforceBridgePolicy(ctx context.Context, pod *corev1.Pod, interfaces []Interface, policy *datastore.Policy, logger logr.Logger) error {
	nft, err := knftables.New(knftables.BridgeFamily, tableName)
	if err != nil {
		return fmt.Errorf("failed to create bridge nftables client: %w", err)
	}
	if err := cleanUp(ctx, nft, policy.Name, policy.Namespace, logger); err != nil {
		return fmt.Errorf("failed to clean up bridge policy: %w", err)
	}
	if !utils.MatchesSelector(policy.Spec.PodSelector, pod.Labels) {
		return nil
	}
	matchedInterfaces := getMatchedInterfaces(interfaces, policy.Networks)
	if len(matchedInterfaces) == 0 {
		return nil
	}
	if err := ensureBridgeStructure(ctx, nft, n.CommonRules, logger); err != nil {
		return err
	}

	hashName := utils.GetHashName(policy.Name, policy.Namespace)
	policyChain := prefixNetworkPolicyChain + hashName
	comment := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	ingressEnabled, egressEnabled := checkPolicyTypes(policy)
	tx := nft.NewTransaction()
	createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

	// Both iifname and oifname exist on a forwarded packet. Use different
	// per-policy chains so an egress permission cannot admit ingress traffic.
	if ingressEnabled {
		chain := policyChain + "-" + ingressChain
		createBridgeDispatcherRule(tx, hashName, forwardIngressChain, "iifname", ingressChain, comment)
		if err := createPolicyChain(ctx, nft, tx, chain, ingressChain, policy.Namespace, policy.Name, logger); err != nil {
			return err
		}
		// The inet backend's local-stack reverse/hairpin allowance is not an
		// authorization for transit traffic to use the endpoint's source IP.
		if err := n.createIngressRulesForChain(ctx, tx, matchedInterfaces, policy, hashName, chain, logger); err != nil {
			return err
		}
	}
	if egressEnabled {
		chain := policyChain + "-" + egressChain
		createBridgeDispatcherRule(tx, hashName, forwardEgressChain, "oifname", egressChain, comment)
		if err := createPolicyChain(ctx, nft, tx, chain, egressChain, policy.Namespace, policy.Name, logger); err != nil {
			return err
		}
		if err := n.createEgressRulesForChain(ctx, tx, matchedInterfaces, policy, hashName, chain, logger); err != nil {
			return err
		}
	}
	if err := nft.Run(ctx, tx); err != nil {
		return fmt.Errorf("failed to apply bridge policy: %w", err)
	}
	return nil
}

func ensureBridgeStructure(ctx context.Context, nft knftables.Interface, commonRules *CommonRules, logger logr.Logger) error {
	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{Comment: knftables.PtrTo("MultiNetworkPolicy bridge forwarding")})
	// Separate base chains ensure accepting ingress does not skip egress
	// enforcement when the outgoing port also belongs to a managed network.
	for i, name := range []string{forwardIngressChain, forwardEgressChain} {
		tx.Add(&knftables.Chain{
			Name:     name,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.ForwardHook),
			Priority: knftables.PtrTo(knftables.BaseChainPriority(fmt.Sprint(i * 10))),
			Policy:   knftables.PtrTo(knftables.AcceptPolicy),
		})
	}
	if err := policyTypeStructure(ctx, nft, tx, ingressChain, "Ingress Policies", commonIngressChain, logger); err != nil {
		return err
	}
	if err := policyTypeStructure(ctx, nft, tx, egressChain, "Egress Policies", commonEgressChain, logger); err != nil {
		return err
	}
	createCommonRules(tx, commonRules, logger)
	if err := nft.Run(ctx, tx); err != nil {
		return fmt.Errorf("failed to initialize bridge policy structure: %w", err)
	}
	return nil
}

func createBridgeDispatcherRule(tx *knftables.Transaction, hashName, dispatcher, interfaceKey, target, comment string) {
	tx.Add(&knftables.Rule{
		Chain: dispatcher,
		// Match the protocol in skb metadata: ether type can expose a VLAN
		// header even when the networking stack has decoded its inner IP packet.
		// Non-IP traffic, including ARP, does not enter the IP policy chains.
		Rule:    knftables.Concat("meta protocol { ip, ip6 }", interfaceKey, "@"+prefixManagedInterfacesSet+hashName, "jump", target),
		Comment: knftables.PtrTo(comment),
	})
}
