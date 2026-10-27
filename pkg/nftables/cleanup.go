package nftables

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"sigs.k8s.io/knftables"

	"github.com/k8snetworkplumbingwg/multi-network-policy-nftables/pkg/utils"
)

// cleanUpPolicy cleans up the policy
func cleanUpPolicy(ctx context.Context, policyName string, policyNamespace string, logger logr.Logger) error {
	for _, family := range []knftables.Family{knftables.InetFamily, knftables.BridgeFamily} {
		nft, err := knftables.New(family, tableName)
		if err != nil {
			return fmt.Errorf("failed to create %s nftables client: %w", family, err)
		}
		if err := cleanUp(ctx, nft, policyName, policyNamespace, logger); err != nil {
			return err
		}
	}
	return nil
}

// cleanUp cleans up the policy chains, rules and sets
func cleanUp(ctx context.Context, nft knftables.Interface, policyName string, policyNamespace string, logger logr.Logger) error {
	logger.Info("Cleaning up policy")

	tx := nft.NewTransaction()

	policyRuleComment := fmt.Sprintf("%s/%s", policyNamespace, policyName)

	// A policy may have dispatchers in either family. Missing chains are normal.
	for _, chain := range []string{inputChain, outputChain, forwardIngressChain, forwardEgressChain, ingressChain, egressChain} {
		rules, err := nft.ListRules(ctx, chain)
		if err != nil && !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list rules in %s chain: %w", chain, err)
		}
		for _, rule := range rules {
			if rule.Comment != nil && *rule.Comment == policyRuleComment {
				logger.V(1).Info("Deleting policy dispatcher", "chain", chain, "rule", rule.Comment)
				tx.Delete(rule)
			}
		}
	}

	hashName := utils.GetHashName(policyName, policyNamespace)

	// Delete policy chains
	chains, err := nft.List(ctx, "chains")
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list chains: %w", err)
		}
	}

	for _, chain := range chains {
		base := fmt.Sprintf("%s%s", prefixNetworkPolicyChain, hashName)
		if chain == base || chain == base+"-"+ingressChain || chain == base+"-"+egressChain {
			logger.V(1).Info("Deleting policy chain", "chain", chain)
			tx.Flush(&knftables.Chain{
				Name: chain,
			})

			tx.Delete(&knftables.Chain{
				Name: chain,
			})
		}
	}

	// Delete policy sets
	policySetPrefix := fmt.Sprintf("%s%s", prefixNetworkPolicySet, hashName)
	managedInterfacesSetPrefix := fmt.Sprintf("%s%s", prefixManagedInterfacesSet, hashName)

	// Delete policy sets
	sets, err := nft.List(ctx, "sets")
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list sets: %w", err)
		}
	}

	for _, set := range sets {
		if strings.HasPrefix(set, policySetPrefix) || strings.HasPrefix(set, managedInterfacesSetPrefix) {
			logger.V(1).Info("Deleting policy set", "set", set)
			tx.Flush(&knftables.Set{
				Name: set,
			})

			tx.Delete(&knftables.Set{
				Name: set,
			})
		}
	}

	if logger.V(1).Enabled() {
		logger.V(1).Info("Applying nftables cleanup transaction", "transaction", tx.String())
	}

	err = nft.Run(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to run transaction: %w", err)
	}

	return nil
}
