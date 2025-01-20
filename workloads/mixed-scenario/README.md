
## Mixed Scenario for ANP/NetworkPolicy/EgressFirewall

With the help of [Mixed Scenario for ANP/NetworkPolicy/EgressFirewall] customer use cases, the test case combined with node-density-heavy, anp, network policy and egress firewall test scenario. To simulate large scale workload in zero-trust OCP cluster, the network traffic of egress and ingress denied by default. 

## How to run mixed-scenario tests?

The environmental variables and steps to kick off this test can be found [here](https://github.com/cloud-bulldozer/e2e-benchmarking/blob/master/workloads/kube-burner/README.md#kube-burner-e2e-benchmarks)

## What are the test cases that this workload can currently run?

### Recommend settings for large namespaces

- Only create BANP and ANP using below environments, the case can be used for ANP benchmarking
```export MAX_INGRESS_CONTROLLER=100
export EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM=9
export ENABLE_INGRESS_CONTROLLER=false
export IF_SLEEP_WAIT_IN_EACH_PHASE=false
export POD_RPLICAS=1
export GC=false
export ENABLE_EGRESS_FIREWALL_POLICY=false
export ENABLE_NETWORK_POLICY=false
export NO_VERIFY_ANP=false

export CHURN=false
export BURST=35
export QPS=30
```
- It will create 7 X ITERATIONS namespace and 4 pods each NS by default, the example of NS is anp-restricted, anp-open, anp-test, anp-unknown, anp-node, anp-cidr and anp-pcidr, the script will create 3 type ANPs(Pod Selecotr, CIDR Select, HOST IP Selector)
