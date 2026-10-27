package nftables

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/knftables"

	"github.com/k8snetworkplumbingwg/multi-network-policy-nftables/pkg/datastore"
)

// Helpers run as subprocesses so every Go socket is created in the intended
// network namespace, including sockets opened by the runtime on other threads.
// The apply/cleanup modes also let the external DHCP lab exercise the actual
// upstream policy generator without requiring a Kubernetes API or CRI server.
func TestMain(m *testing.M) {
	if mode := os.Getenv("NMP_TEST_HELPER"); mode != "" {
		if err := runBridgeTestHelper(mode); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type bridgeTestPolicyRequest struct {
	Pod         corev1.Pod       `json:"pod"`
	Policy      datastore.Policy `json:"policy"`
	Peers       []corev1.Pod     `json:"peers,omitempty"`
	CommonRules *CommonRules     `json:"commonRules,omitempty"`
}

func runBridgeTestHelper(mode string) error {
	switch mode {
	case "serve":
		listener, err := net.Listen("tcp", ":"+os.Getenv("NMP_TEST_PORT"))
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintln(os.Stdout, "READY")
		for {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = fmt.Fprintln(conn, os.Getenv("NMP_TEST_ROLE"))
			_ = conn.Close()
		}
	case "client":
		conn, err := net.DialTimeout("tcp", os.Getenv("NMP_TEST_ADDRESS"), 500*time.Millisecond)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stdout, line)
		return nil
	case "pump":
		return bridgeTestTAPPump(os.Getenv("NMP_TEST_LAUNCH_NS"), os.Getenv("NMP_TEST_GUEST_NS"))
	case "apply", "cleanup":
		input, err := os.Open(os.Getenv("NMP_TEST_POLICY_FILE"))
		if err != nil {
			return err
		}
		defer input.Close()
		var request bridgeTestPolicyRequest
		if err := json.NewDecoder(input).Decode(&request); err != nil {
			return err
		}
		if mode == "cleanup" {
			return cleanUpPolicy(context.Background(), request.Policy.Name, request.Policy.Namespace, logr.Discard())
		}
		pods := []*corev1.Pod{&request.Pod}
		for i := range request.Peers {
			pods = append(pods, &request.Peers[i])
		}
		engine := &NFTables{Client: createFakeClient(pods), CommonRules: request.CommonRules}
		return engine.enforcePolicy(context.Background(), &request.Pod, getInterfaces(&request.Pod), &request.Policy, logr.Discard())
	default:
		return fmt.Errorf("unknown bridge test helper %q", mode)
	}
}

func bridgeTestTAPPump(launcher, guest string) error {
	open := func(path, name string) (*os.File, error) {
		netns, err := ns.GetNS(path)
		if err != nil {
			return nil, err
		}
		defer netns.Close()
		var tap *os.File
		err = netns.Do(func(_ ns.NetNS) error {
			fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			ifr, err := unix.NewIfreq(name)
			if err == nil {
				ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
				err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
			}
			if err != nil {
				_ = unix.Close(fd)
				return err
			}
			tap = os.NewFile(uintptr(fd), name)
			return nil
		})
		return tap, err
	}
	left, err := open(launcher, "tap0")
	if err != nil {
		return err
	}
	defer left.Close()
	right, err := open(guest, "guest0")
	if err != nil {
		return err
	}
	defer right.Close()
	errors := make(chan error, 2)
	copyPackets := func(dst, src *os.File) {
		buffer := make([]byte, 65536)
		for {
			n, err := src.Read(buffer)
			if err != nil {
				errors <- err
				return
			}
			written, err := dst.Write(buffer[:n])
			if err != nil {
				errors <- err
				return
			}
			if written != n {
				errors <- io.ErrShortWrite
				return
			}
		}
	}
	go copyPackets(right, left)
	go copyPackets(left, right)
	fmt.Fprintln(os.Stdout, "READY")
	return <-errors
}

type bridgeFixture struct {
	launcher ns.NetNS
	peer     ns.NetNS
	guest    ns.NetNS
	nets     []ns.NetNS
	children []*exec.Cmd
	pod      *corev1.Pod
	engine   *NFTables
}

func newBridgeFixture() *bridgeFixture {
	f := &bridgeFixture{}
	DeferCleanup(func() {
		for _, child := range f.children {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		for _, netns := range f.nets {
			Expect(netns.Close()).To(Succeed())
			Expect(testutils.UnmountNS(netns)).To(Succeed())
		}
	})
	for range 3 {
		netns, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		f.nets = append(f.nets, netns)
		f.run(netns, "ip", "link", "set", "lo", "up")
		f.run(netns, "sysctl", "-qw", "net.ipv6.conf.default.accept_dad=0", "net.ipv6.conf.default.accept_ra=0", "net.ipv6.conf.default.autoconf=0")
	}
	f.launcher, f.peer, f.guest = f.nets[0], f.nets[1], f.nets[2]
	f.run(f.peer, "ip", "link", "add", "peer0", "type", "veth", "peer", "name", "net1", "netns", filepath.Base(f.launcher.Path()))
	f.link(f.peer, "peer0", "02:00:00:00:00:01", "192.0.2.1/24", "2001:db8:1::1/64")
	f.link(f.launcher, "net1", "02:00:00:00:00:10", "", "")
	f.start(f.launcher, "pump", "NMP_TEST_LAUNCH_NS="+f.launcher.Path(), "NMP_TEST_GUEST_NS="+f.guest.Path())
	f.link(f.launcher, "tap0", "02:00:00:00:00:20", "", "")
	f.link(f.guest, "guest0", "02:00:00:00:00:10", "192.0.2.100/24", "2001:db8:1::100/64")
	f.run(f.launcher, "ip", "link", "add", "br0", "address", "02:00:00:00:00:30", "type", "bridge", "stp_state", "0", "mcast_snooping", "0")
	f.run(f.launcher, "sysctl", "-qw", "net.ipv6.conf.br0.disable_ipv6=1")
	f.run(f.launcher, "ip", "link", "set", "br0", "up")
	f.run(f.launcher, "ip", "link", "set", "net1", "master", "br0")
	f.run(f.launcher, "ip", "link", "set", "tap0", "master", "br0")
	// The guest shares the CNI NIC's MAC. Replace the bridge-local FDB entry
	// with a forwarding entry; the original NIC itself stays unchanged.
	f.run(f.launcher, "bridge", "fdb", "replace", "02:00:00:00:00:10", "dev", "tap0", "master", "static")
	f.start(f.peer, "serve", "NMP_TEST_PORT=18081", "NMP_TEST_ROLE=peer")
	f.start(f.guest, "serve", "NMP_TEST_PORT=18080", "NMP_TEST_ROLE=guest")
	f.start(f.guest, "serve", "NMP_TEST_PORT=18082", "NMP_TEST_ROLE=guest")
	f.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "launcher", Namespace: "test-ns", Labels: map[string]string{"app": "web"},
		Annotations: map[string]string{
			"k8s.v1.cni.cncf.io/networks":       "secondary",
			"k8s.v1.cni.cncf.io/network-status": `[{"name":"test-ns/secondary","interface":"net1","ips":[]}]`,
		},
	}}
	f.pod.Status.Phase = corev1.PodRunning
	peer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "peer", Namespace: "test-ns", Labels: map[string]string{"app": "peer"},
		Annotations: map[string]string{
			"k8s.v1.cni.cncf.io/networks":       "secondary",
			"k8s.v1.cni.cncf.io/network-status": `[{"name":"test-ns/secondary","interface":"peer0","ips":["192.0.2.1","2001:db8:1::1"]}]`,
		},
	}}
	peer.Status.Phase = corev1.PodRunning
	f.engine = &NFTables{Client: createFakeClient([]*corev1.Pod{f.pod, peer}), CommonRules: &CommonRules{AcceptICMPv6: true}}
	// Establish fixture health before testing policy drops. Each subsequent
	// probe uses a new TCP connection rather than an already-established flow.
	f.checkBoth(true, true)
	return f
}

func (f *bridgeFixture) command(netns ns.NetNS, args ...string) *exec.Cmd {
	cmd := exec.Command("ip", append([]string{"netns", "exec", filepath.Base(netns.Path())}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd
}

func (f *bridgeFixture) run(netns ns.NetNS, args ...string) {
	cmd := f.command(netns, args...)
	output, err := cmd.CombinedOutput()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "%s: %s", cmd.String(), output)
}

func (f *bridgeFixture) link(netns ns.NetNS, name, mac, ipv4, ipv6 string) {
	f.run(netns, "ip", "link", "set", name, "address", mac)
	if ipv4 == "" && ipv6 == "" {
		f.run(netns, "sysctl", "-qw", "net.ipv6.conf."+name+".disable_ipv6=1")
	}
	f.run(netns, "ip", "link", "set", name, "up")
	if ipv4 != "" {
		f.run(netns, "ip", "addr", "add", ipv4, "dev", name)
	}
	if ipv6 != "" {
		f.run(netns, "ip", "-6", "addr", "add", ipv6, "dev", name, "nodad")
	}
}

func (f *bridgeFixture) start(netns ns.NetNS, mode string, env ...string) {
	cmd := f.command(netns, os.Args[0])
	cmd.Env = append(os.Environ(), append([]string{"NMP_TEST_HELPER=" + mode}, env...)...)
	stdout, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	cmd.Stderr = GinkgoWriter
	Expect(cmd.Start()).To(Succeed())
	f.children = append(f.children, cmd)
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	Eventually(ready, 5*time.Second).Should(Receive(Equal("READY")))
}

func (f *bridgeFixture) check(netns ns.NetNS, address, role string, allowed bool) {
	cmd := f.command(netns, os.Args[0])
	cmd.Env = append(os.Environ(), "NMP_TEST_HELPER=client", "NMP_TEST_ADDRESS="+address)
	output, err := cmd.CombinedOutput()
	if allowed {
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "%s: %s", address, output)
		ExpectWithOffset(1, strings.TrimSpace(string(output))).To(Equal(role))
	} else {
		ExpectWithOffset(1, err).To(HaveOccurred(), "unexpected connection to %s: %s", address, output)
		ExpectWithOffset(1, string(output)).To(ContainSubstring("timeout"), "a policy drop should time out, rather than connect to a missing listener")
	}
}

func (f *bridgeFixture) checkBoth(ingress, egress bool) {
	f.check(f.peer, "192.0.2.100:18080", "guest", ingress)
	f.check(f.guest, "192.0.2.1:18081", "peer", egress)
	f.check(f.peer, "[2001:db8:1::100]:18080", "guest", ingress)
	f.check(f.guest, "[2001:db8:1::1]:18081", "peer", egress)
}

func (f *bridgeFixture) apply(policy *datastore.Policy) {
	ExpectWithOffset(1, f.launcher.Do(func(_ ns.NetNS) error {
		return f.engine.enforcePolicy(context.Background(), f.pod, getInterfaces(f.pod), policy, logr.Discard())
	})).To(Succeed())
}

func (f *bridgeFixture) remove(policy *datastore.Policy) {
	ExpectWithOffset(1, f.launcher.Do(func(_ ns.NetNS) error {
		return cleanUpPolicy(context.Background(), policy.Name, policy.Namespace, logr.Discard())
	})).To(Succeed())
}

func bridgeTestPolicy(name string, ingress, egress bool) *datastore.Policy {
	p := createDenyAllPolicy(name, "test-ns")
	p.Networks = []string{"test-ns/secondary"}
	if ingress {
		p.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{{}}
	}
	if egress {
		p.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{{}}
	}
	return p
}

func bridgePeerPolicy() *datastore.Policy {
	p := bridgeTestPolicy("allow-peer", false, false)
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "peer"}}
	ingressPort, egressPort := intstr.FromInt32(18080), intstr.FromInt32(18081)
	p.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{{
		From:  []multiv1beta1.MultiNetworkPolicyPeer{{PodSelector: selector}},
		Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &ingressPort}},
	}}
	p.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{{
		To:    []multiv1beta1.MultiNetworkPolicyPeer{{PodSelector: selector}},
		Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &egressPort}},
	}}
	return p
}

var _ = Describe("Bridge forwarding datapath", func() {
	var f *bridgeFixture
	BeforeEach(func() { f = newBridgeFixture() })

	DescribeTable("enforces directions independently on an unnumbered NIC", func(ingress, egress bool) {
		f.apply(bridgeTestPolicy("direction-test", ingress, egress))
		f.checkBoth(ingress, egress)
		Expect(getInterfaces(f.pod)).To(Equal([]Interface{{Name: "net1", Network: "test-ns/secondary", IPs: []string{}}}))
	},
		Entry("ingress denied, outgoing connections and their replies allowed", false, true),
		Entry("egress denied, incoming connections and their replies allowed", true, false),
		Entry("both denied", false, false),
	)

	It("unions policies and removes only the deleted policy's permissions", func() {
		deny, allow := bridgeTestPolicy("deny", false, false), bridgePeerPolicy()
		f.apply(deny)
		f.checkBoth(false, false)
		f.apply(allow)
		f.checkBoth(true, true)
		f.check(f.peer, "192.0.2.100:18082", "guest", false)
		f.remove(allow)
		f.checkBoth(false, false)
		f.remove(deny)
		f.checkBoth(true, true)
	})

	It("rebuilds peer selector sets when a policy is reapplied", func() {
		policy := bridgePeerPolicy()
		f.apply(policy)
		f.checkBoth(true, true)
		peer := &corev1.Pod{}
		Expect(f.engine.Get(context.Background(), types.NamespacedName{Namespace: "test-ns", Name: "peer"}, peer)).To(Succeed())
		peer.Annotations["k8s.v1.cni.cncf.io/network-status"] = `[{"name":"test-ns/secondary","interface":"peer0","ips":["192.0.2.254","2001:db8:1::254"]}]`
		Expect(f.engine.Update(context.Background(), peer)).To(Succeed())
		f.apply(policy)
		f.checkBoth(false, false)
	})

	DescribeTable("requires both permissions when both bridge ports are policy-managed", func(ingress, egress bool) {
		f.pod.Annotations["k8s.v1.cni.cncf.io/networks"] = "secondary,downstream"
		f.pod.Annotations["k8s.v1.cni.cncf.io/network-status"] = `[{"name":"test-ns/secondary","interface":"net1","ips":[]},{"name":"test-ns/downstream","interface":"tap0","ips":[]}]`
		policy := bridgeTestPolicy("both-ports", ingress, egress)
		policy.Networks = append(policy.Networks, "test-ns/downstream")
		f.apply(policy)
		f.check(f.peer, "192.0.2.100:18080", "guest", ingress && egress)
	},
		Entry("egress allow cannot bypass ingress deny", false, true),
		Entry("ingress accept cannot bypass the later egress deny", true, false),
		Entry("both permissions allow traffic", true, true),
	)

	It("does not use the local-stack reverse-IP exemption for transit traffic", func() {
		f.pod.Annotations["k8s.v1.cni.cncf.io/network-status"] = `[{"name":"test-ns/secondary","interface":"net1","ips":["192.0.2.1"]}]`
		f.apply(bridgeTestPolicy("no-transit-exemption", false, true))
		f.check(f.peer, "192.0.2.100:18080", "guest", false)
	})

	It("applies configured common rules to forwarded traffic", func() {
		f.engine.CommonRules.CustomIPv4IngressRules = []string{"ip saddr 192.0.2.1 tcp dport 18082 accept"}
		f.apply(bridgeTestPolicy("common-rule", false, false))
		f.check(f.peer, "192.0.2.100:18082", "guest", true)
		f.check(f.peer, "192.0.2.100:18080", "guest", false)
	})

	It("preserves ordinary local endpoint policy enforcement alongside the bridge", func() {
		f.run(f.peer, "ip", "link", "add", "local-peer", "type", "veth", "peer", "name", "local0", "netns", filepath.Base(f.launcher.Path()))
		f.link(f.peer, "local-peer", "02:00:00:00:01:01", "203.0.113.1/24", "")
		f.link(f.launcher, "local0", "02:00:00:00:01:10", "203.0.113.10/24", "")
		f.start(f.launcher, "serve", "NMP_TEST_PORT=19080", "NMP_TEST_ROLE=local")
		f.check(f.peer, "203.0.113.10:19080", "local", true)
		f.pod.Annotations["k8s.v1.cni.cncf.io/networks"] = "secondary,local-network"
		f.pod.Annotations["k8s.v1.cni.cncf.io/network-status"] = `[{"name":"test-ns/secondary","interface":"net1","ips":[]},{"name":"test-ns/local-network","interface":"local0","ips":["203.0.113.10"]}]`
		policy := bridgeTestPolicy("local-deny", false, false)
		policy.Networks = []string{"test-ns/local-network"}
		f.apply(policy)
		f.check(f.peer, "203.0.113.10:19080", "local", false)
		f.check(f.launcher, "203.0.113.1:18081", "peer", false)
		f.checkBoth(true, true)
	})

	It("filters single-tagged VLAN IP traffic rather than bypassing IP policies", func() {
		for _, endpoint := range []struct {
			netns           ns.NetNS
			parent, address string
		}{
			{f.peer, "peer0", "198.18.0.1/24"}, {f.guest, "guest0", "198.18.0.100/24"},
		} {
			f.run(endpoint.netns, "ip", "link", "add", "link", endpoint.parent, "name", "vlan100", "type", "vlan", "id", "100")
			f.run(endpoint.netns, "ip", "link", "set", "vlan100", "up")
			f.run(endpoint.netns, "ip", "addr", "add", endpoint.address, "dev", "vlan100")
		}
		f.check(f.peer, "198.18.0.100:18080", "guest", true)
		f.apply(bridgeTestPolicy("deny", false, false))
		f.check(f.peer, "198.18.0.100:18080", "guest", false)
		allow := bridgePeerPolicy()
		allow.Spec.Ingress[0].From = []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "198.18.0.1/32"}}}
		allow.Spec.Egress[0].To = []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "198.18.0.1/32"}}}
		f.apply(allow)
		f.check(f.peer, "198.18.0.100:18080", "guest", true)
		f.check(f.guest, "198.18.0.1:18081", "peer", true)
	})

	It("removes stale forwarding permissions when the pod stops matching", func() {
		policy := bridgeTestPolicy("selection", false, false)
		f.apply(policy)
		f.checkBoth(false, false)
		policy.Spec.PodSelector.MatchLabels["app"] = "another-workload"
		f.apply(policy)
		f.checkBoth(true, true)
		Expect(f.launcher.Do(func(_ ns.NetNS) error {
			for _, family := range []knftables.Family{knftables.InetFamily, knftables.BridgeFamily} {
				nft, err := knftables.New(family, tableName)
				if err != nil {
					return err
				}
				sets, err := nft.List(context.Background(), "sets")
				if err != nil {
					return err
				}
				if len(sets) != 0 {
					return fmt.Errorf("stale %s policy sets: %v", family, sets)
				}
			}
			return nil
		})).To(Succeed())
	})
})
