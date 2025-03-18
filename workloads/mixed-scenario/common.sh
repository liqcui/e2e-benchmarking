#!/usr/bin/bash
source ../../utils/common.sh
# set -o nounset
# set -o errexit
# set -o pipefail
#source env.sh

openshift_login

# If INDEXING is enabled we retrive the prometheus oauth token
if [[ ${INDEXING} == "true" ]]; then
  if [[ ${HYPERSHIFT} == "false" ]]; then
    export PROM_TOKEN=$(oc create token -n openshift-monitoring prometheus-k8s --duration=6h || oc sa get-token -n openshift-monitoring prometheus-k8s || oc sa new-token -n openshift-monitoring prometheus-k8s)
  else
    export PROM_TOKEN="dummytokenforthanos"
    export HOSTED_CLUSTER_NAME=$(oc get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
  fi
fi
export UUID=${UUID:-$(uuidgen)}
export OPENSHIFT_VERSION=$(oc version -o json | jq -r '.openshiftVersion') 
export NETWORK_TYPE=$(oc get network.config/cluster -o jsonpath='{.status.networkType}') 
export INGRESS_DOMAIN=$(oc get IngressController default -n openshift-ingress-operator -o jsonpath='{.status.domain}' || oc get routes -A --no-headers | head -n 1 | awk {'print$3'} | cut -d "." -f 2-)

platform=$(oc get infrastructure cluster -o jsonpath='{.status.platformStatus.type}')

if [[ ${HYPERSHIFT} == "true" ]]; then
  # shellcheck disable=SC2143
  if oc get ns grafana-agent; then
    log "Grafana agent is already installed"
  else
    export CLUSTER_NAME=${HOSTED_CLUSTER_NAME}
    export PLATFORM=$(oc get infrastructure cluster -o jsonpath='{.status.platformStatus.type}')
    export DAG_ID=$(oc version -o json | jq -r '.openshiftVersion')-$(oc get infrastructure cluster -o jsonpath='{.status.infrastructureName}') # setting a dynamic value
    envsubst < ./grafana-agent.yaml | oc apply -f -
  fi
  echo "Get all management worker nodes.."
  export Q_TIME=$(date +"%s")
  export Q_NODES=""
  for n in $(curl -k --silent --globoff  ${PROM_URL}/api/v1/query?query='sum(kube_node_role{openshift_cluster_name=~"'${MGMT_CLUSTER_NAME}'",role=~"master|infra|workload"})by(node)&time='$(($Q_TIME-300))'' | jq -r '.data.result[].metric.node'); do
    Q_NODES=${n}"|"${Q_NODES};
  done
  export MGMT_NON_WORKER_NODES=${Q_NODES}
  # set time for modifier queries 
  export Q_TIME=$(($Q_TIME+600))
fi

collect_pprof() {
  sleep 50
  while [ $(oc get benchmark -n benchmark-operator kube-burner-${1}-${UUID} -o jsonpath="{.status.complete}") == "false" ]; do
    log "-----------------------checking for new pprof files--------------------------"
    oc rsync -n benchmark-operator $(oc get pod -n benchmark-operator -o name -l benchmark-uuid=${UUID}):/tmp/pprof-data $PWD/
    sleep 60
  done
}

run_workload() {
  local CMD
  local KUBE_BURNER_DIR 
  KUBE_BURNER_DIR=$(mktemp -d)
  if [[ ! -d ${KUBE_DIR} ]]; then
    mkdir -p ${KUBE_DIR}
  fi
  if [[ -n ${BUILD_FROM_REPO} ]]; then
    git clone --depth=1 ${BUILD_FROM_REPO} ${KUBE_BURNER_DIR}
    make -C ${KUBE_BURNER_DIR} build
    mv ${KUBE_BURNER_DIR}/bin/amd64/kube-burner ${KUBE_DIR}/kube-burner
    rm -rf ${KUBE_BURNER_DIR}
  else
    curl -sS -L ${KUBE_BURNER_URL} | tar -xzC ${KUBE_DIR}/ kube-burner
  fi
  CMD="timeout ${JOB_TIMEOUT} ${KUBE_DIR}/kube-burner init --uuid=${UUID} -c $(basename ${WORKLOAD_TEMPLATE}) --log-level=${LOG_LEVEL}"

  # When metrics or alerting are enabled we have to pass the prometheus URL to the cmd
  if [[ ${INDEXING} == "true" ]] || [[ ${PLATFORM_ALERTS} == "true" ]] ; then
    CMD+=" -u=${PROM_URL} -t ${PROM_TOKEN}"
  fi
  if [[ -n ${METRICS_PROFILE} ]]; then
    log "Indexing enabled, using metrics from ${METRICS_PROFILE}"
    envsubst < ${METRICS_PROFILE} > ${KUBE_DIR}/metrics.yml
    CMD+=" -m ${KUBE_DIR}/metrics.yml"
  fi
  if [[ ${PLATFORM_ALERTS} == "true" ]]; then
    log "Platform alerting enabled, using ${PWD}/alerts-profiles/${WORKLOAD}-${platform}.yml"
    CMD+=" -a ${PWD}/alerts-profiles/${WORKLOAD}-${platform}.yml"
  fi
  pushd $(dirname ${WORKLOAD_TEMPLATE})
  local start_date=$(date +%s%3N)
  ${CMD}
  rc=$?
  popd
  if [[ ${rc} == 0 ]]; then
    RESULT=Complete
  else
    RESULT=Failed
  fi
  gen_metadata ${WORKLOAD} ${start_date} $(date +%s%3N)
}

find_running_pods_num() {
  pod_count=0
  # The next statement outputs something similar to:
  # ip-10-0-177-166.us-west-2.compute.internal:20
  # ip-10-0-250-197.us-west-2.compute.internal:17
  # ip-10-0-151-0.us-west-2.compute.internal:19
  NODE_PODS=$(kubectl get pods --field-selector=status.phase=Running -o go-template --template='{{range .items}}{{.spec.nodeName}}{{"\n"}}{{end}}' -A | awk '{nodes[$1]++ }END{ for (n in nodes) print n":"nodes[n]}')
  for worker_node in ${WORKER_NODE_NAMES}; do
    for node_pod in ${NODE_PODS}; do
      # We use awk to match the node name and then we take the number of pods, which is the number after the colon
      pods=$(echo "${node_pod}" | awk -F: '/'$worker_node'/{print $2}')
      pod_count=$((pods + pod_count))
    done
  done
  log "Total running pods across nodes: ${pod_count}"
  # Number of pods to deploy per node * number of labeled nodes - pods running
  total_pod_count=$((PODS_PER_NODE * NODE_COUNT - pod_count))
  log "Number of pods to deploy on nodes: ${total_pod_count}"
  if [[ ${1} == "heavy" ]] || [[ ${1} == *cni* ]]; then
    total_pod_count=$((total_pod_count / 2))
  fi
  if [[ ${total_pod_count} -le 0 ]]; then
    log "Number of pods to deploy <= 0"
    exit 1
  fi
  export TEST_JOB_ITERATIONS=${total_pod_count}
}

cleanup() {
  log "Cleaning up benchmark assets"
  if ! oc delete ns -l kube-burner-uuid=${UUID} --grace-period=600 --timeout=${CLEANUP_TIMEOUT} 1>/dev/null; then
    log "Namespaces cleanup failure"
    rc=1
  fi
}

get_pprof_secrets() {
  if [[ ${HYPERSHIFT} == "true" ]]; then
    log "Control Plane not available in HyperShift"
    exit 1
  else
    oc create ns benchmark-operator
    oc create serviceaccount kube-burner -n benchmark-operator
    oc create clusterrolebinding kube-burner-crb --clusterrole=cluster-admin --serviceaccount=benchmark-operator:kube-burner
    local certkey=`oc get secret -n openshift-etcd | grep "etcd-serving-ip" | head -1 | awk '{print $1}'`
    oc extract -n openshift-etcd secret/$certkey
    export CERTIFICATE=`base64 -w0 tls.crt`
    export PRIVATE_KEY=`base64 -w0 tls.key`
    export BEARER_TOKEN=$(oc create token -n benchmark-operator kube-burner --duration=6h || oc sa get-token kube-burner -n benchmark-operator)
  fi
}

delete_pprof_secrets() {
 rm -f tls.key tls.crt
}

delete_oldpprof_folder() {
 rm -rf pprof-data
}

label_node_with_label() {
  colon_param=$(echo $1 | tr "=" ":" | sed 's/:/: /g')
  export POD_NODE_SELECTOR="{$colon_param}"
  if [[ -z $NODE_COUNT ]]; then
    NODE_COUNT=$(oc get node -o name --no-headers -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= | wc -l )
  fi
  if [[ ${NODE_COUNT} -le 0 ]]; then
    log "Node count <= 0: ${NODE_COUNT}"
    exit 1
  fi
  WORKER_NODE_NAMES=$(oc get node -o custom-columns=name:.metadata.name --no-headers -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= | head -n ${NODE_COUNT})
  if [[ $(echo "${WORKER_NODE_NAMES}" | wc -l) -lt ${NODE_COUNT} ]]; then
    log "Not enough worker nodes to label"
    exit 1
  fi

  log "Labeling ${NODE_COUNT} worker nodes with $1"
  oc label node ${WORKER_NODE_NAMES} $1 --overwrite 1>/dev/null
}

unlabel_nodes_with_label() {
  split_param=$(echo $1 | tr "=" " ")
  log "Removing $1 label from worker nodes"
  for worker_node in ${WORKER_NODE_NAMES}; do
    for p in ${split_param}; do
      oc label node $worker_node $p- 1>/dev/null
      break
    done
  done
}

prep_networkpolicy_workload() {
  export ES_INDEX_NETPOL=${ES_INDEX_NETPOL:-networkpolicy-enforcement}
  oc apply -f workloads/networkpolicy/clusterrole.yml
  oc apply -f workloads/networkpolicy/clusterrolebinding.yml
}

#Mixed Scenario
function generated_egress_firewall_policy(){

  EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=${EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH:=""}
  if [[ -z $EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH ]];then
	echo "Please specify EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH for template path and file name"
	exit 1
  fi
  EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM=$1
  if [[ $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM -le 4 ]];then
	  echo "Please specify a number that large than 4 for EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM"
	  exit 1
  fi
  EGRESS_FIREWALL_POLICY_IP_SEGMENT_ALLOW=${EGRESS_FIREWALL_POLICY_IP_SEGMENT_DENY:="5.110.1"}
  EGRESS_FIREWALL_POLICY_IP_SEGMENT_DENY=${EGRESS_FIREWALL_POLICY_IP_SEGMENT_DENY:="5.112.2"}
  EGRESS_FIREWALL_POLICY_DNS_PREFIX_ALLOW=${EGRESS_FIREWALL_POLICY_DNS_PREFIX_ALLOW:="www.perfscale"}
  EGRESS_FIREWALL_POLICY_DNS_PREFIX_DENY=${EGRESS_FIREWALL_POLICY_DNS_PREFIX_ALLOW:="www.perftest"}
  #Expected set 4 types of policy rule, but already have 4 rules by default, so each type of policy rule should be (total_num - 4)/4
  #ie. 130 policy rule, 126=130-4
  #EGRESS_FIREWALL_POLICY_RULE_IP_NUM=31
  #EGRESS_FIREWALL_POLICY_RULE_DNS_NUM=126-2*31=64
  EGRESS_FIREWALL_POLICY_RULE_TYPE_SUBNUM=$(( ($EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM - 5) / 5 ))
  if [[ $EGRESS_FIREWALL_POLICY_RULE_TYPE_SUBNUM -ge 254 ]];then
        EGRESS_FIREWALL_POLICY_RULE_IP_NUM=${EGRESS_FIREWALL_POLICY_IP_NUM:="254"}
  else
	EGRESS_FIREWALL_POLICY_RULE_IP_NUM=$EGRESS_FIREWALL_POLICY_RULE_TYPE_SUBNUM
  fi
        EGRESS_FIREWALL_POLICY_RULE_DNS_NUM=$(( $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM - 5 - 2 * $EGRESS_FIREWALL_POLICY_RULE_IP_NUM))

  NETWORK_TYPE=`oc get network.config.openshift.io cluster -o jsonpath='{.status.networkType}'`
  echo -e "Creating $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM rules per policy for EgressFirewall/EgressNetworkPolicy\nEGRESS_FIREWALL_POLICY_RULE_IP_NUM is $EGRESS_FIREWALL_POLICY_RULE_IP_NUM\nEGRESS_FIREWALL_POLICY_RULE_DNS_NUM is $EGRESS_FIREWALL_POLICY_RULE_DNS_NUM"
  if [[ $NETWORK_TYPE == "OVNKubernetes" ]];then

  cat>$EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH<<EOF
kind: EgressFirewall
apiVersion: k8s.ovn.org/v1
metadata:
  name: default
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: 8.8.8.8/32
  - type: Deny
    to:
      cidrSelector: 8.8.4.4/32
  - type: Allow
    to:
      dnsName: www.google.com
  - type: Allow
    to:
      dnsName: updates.jenkins.io
  - type: Deny
    to:
      dnsName: www.digitalocean.com
EOF
elif [[ $NETWORK_TYPE == "OpenShiftSDN" ]];then
  cat>$EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH<<EOF
apiVersion: network.openshift.io/v1
kind: EgressNetworkPolicy
metadata:
  name: default
spec:
  egress: 
  - type: Allow
    to:
      cidrSelector: 8.8.8.8/32
  - type: Deny
    to:
      cidrSelector: 8.8.4.4/32
  - type: Allow
    to:
      dnsName: www.google.com
  - type: Allow
    to:
      dnsName: updates.jenkins.io
  - type: Deny
    to:
      dnsName: www.digitalocean.com
EOF
else
     echo "Invalid network type or can not fetch network type(OVNKubernetes or OpenShiftSDN), please check."
fi
 #Allow Rules for IP Segment
 INDEX=1
 while [[ $INDEX -le $EGRESS_FIREWALL_POLICY_RULE_IP_NUM ]];
 do
         echo -e "  - type: Allow\n    to:\n      cidrSelector: ${EGRESS_FIREWALL_POLICY_IP_SEGMENT_ALLOW}.${INDEX}/32">>$EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH
         echo -e "  - type: Deny\n    to:\n      cidrSelector: ${EGRESS_FIREWALL_POLICY_IP_SEGMENT_DENY}.${INDEX}/32">>$EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH
	 INDEX=$(( $INDEX + 1 ))
 done
 #In case odd number divide by 2
 TOTAL_ALLOW_DNS_NUM=$(( $EGRESS_FIREWALL_POLICY_RULE_DNS_NUM/2 ))
 TOTAL_DENY_DNS_NUM=$(( $EGRESS_FIREWALL_POLICY_RULE_DNS_NUM - $TOTAL_ALLOW_DNS_NUM ))
 INDEX=1
 while [[ $INDEX -le $TOTAL_ALLOW_DNS_NUM ]];
 do
	 echo -e "  - type: Allow\n    to:\n      dnsName: ${EGRESS_FIREWALL_POLICY_DNS_PREFIX_ALLOW}${INDEX}.com">>$EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH
	 INDEX=$(( $INDEX + 1 ))
 done
 INDEX=1
 while [[ $INDEX -le $TOTAL_DENY_DNS_NUM ]];
 do
	 echo -e "  - type: Deny\n    to:\n      dnsName: ${EGRESS_FIREWALL_POLICY_DNS_PREFIX_DENY}${INDEX}.com">>$EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH
	 INDEX=$(( $INDEX + 1 ))
 done
}

function verify_if_mcp_be_in_updated_state_by_name() {
	
    MCP_NAME=$1
    oc get mcp |grep $MCP_NAME>/dev/null
    if [[ $? -ne 0 ]];then
       echo "No mcp $MCP_NAME found, please check ..."
       exit 1
    fi
		mcpUpdatingStatus=`oc get mcp $MCP_NAME -ojsonpath='{.status.conditions[?(@.type=="Updating")].status}'`
		mcpUpdatedStatus=`oc get mcp $MCP_NAME -ojsonpath='{.status.conditions[?(@.type=="Updated")].status}'`

		mcpMachineCount=`oc get mcp $MCP_NAME -ojsonpath={..status.machineCount}`
		mcpReadyMachineCount=`oc get mcp $MCP_NAME -ojsonpath={..status.readyMachineCount}`
		mcpUpdatedMachineCount=`oc get mcp $MCP_NAME -ojsonpath={..status.updatedMachineCount}`
		mcpDegradedMachineCount=`oc get mcp $MCP_NAME -ojsonpath={..status.degradedMachineCount}`
		if [[ $mcpUpdatingStatus=="False" && $mcpUpdatedStatus=="True" && $mcpMachineCount == $mcpReadyMachineCount && $mcpMachineCount == $mcpUpdatedMachineCount && $mcpDegradedMachineCount == "0" ]];then
        echo true
    else
        echo false
    fi
}

function getLegcyOVNInfo()
{
  echo "Get master pod roles"
for OVNMASTER in $(oc -n openshift-ovn-kubernetes get pods -l app=ovnkube-master -o custom-columns=NAME:.metadata.name --no-headers); \
   do echo "········································" ; \
   echo "· OVNKube Master: $OVNMASTER ·" ; \
   echo "········································" ; \
   echo 'North' `oc -n openshift-ovn-kubernetes rsh -Tc northd $OVNMASTER ovn-appctl -t /var/run/ovn/ovnnb_db.ctl cluster/status OVN_Northbound | grep Role` ; \
   echo 'South' `oc -n openshift-ovn-kubernetes rsh -Tc northd $OVNMASTER ovn-appctl -t /var/run/ovn/ovnsb_db.ctl cluster/status OVN_Southbound | grep Role`; \
   echo 'VMNDB Memory' `oc -n openshift-ovn-kubernetes rsh -Tc northd $OVNMASTER ovs-appctl -t /var/run/ovn/ovnnb_db.ctl memory/show`; \
   echo "····················"; \
   done

for i in $(oc get node -l node-role.kubernetes.io/master= --no-headers -oname);
do 
	echo "$i:  DB Size" ; 
	oc -n openshift-ovn-kubernetes debug $i --quiet=true -- ls -lh /host/var/lib/ovn/etc; 
	echo "----------OVSDB CLUSTERS----------";
	oc -n openshift-ovn-kubernetes debug $i --quiet=true -- grep -e '^OVSDB CLUSTER ' /host/var/lib/ovn/etc/ovnnb_db.db | cut -d' ' -f1-3 | sort -k3 -n | uniq -c | wc -l;
	echo "----------TOP 10 OVSDB CLUSTER INFO----------";
	oc -n openshift-ovn-kubernetes debug $i --quiet=true -- grep -e '^OVSDB CLUSTER ' /host/var/lib/ovn/etc/ovnnb_db.db | cut -d' ' -f1-3 | sort -k3 -n | uniq -c | sort -k1 -r -n | head -10;
	echo "----------ACL----------";
	POD=`oc -n openshift-ovn-kubernetes get po -l app=ovnkube-master -oname --field-selector=spec.host=${i#node/}`;
	export ACL=`oc -n openshift-ovn-kubernetes exec -c northd $POD -- sh -c 'ovn-nbctl --columns=_uuid --no-leader-only list acl | grep ^_uuid | wc -l';`
  echo $ACL
	echo "----------match ACL----------";
	export MATCH_ACL=`oc -n openshift-ovn-kubernetes exec -c northd $POD -- sh -c 'ovn-nbctl --no-leader-only --columns=match list acl | grep -c ^match';`
  echo $MATCH_ACL
done
}

function getOVNICDBInfo()
{
  
   echo "Get ACL From OVN DB"
   OVNKUBE_CONTROL_PLANE_POD=`oc -n openshift-ovn-kubernetes get lease ovn-kubernetes-master -o=jsonpath={.spec.holderIdentity}`
   echo OVNKUBE_CONTROL_PLANE_POD is $OVNKUBE_CONTROL_PLANE_POD
   NODE_NAME=`oc -n openshift-ovn-kubernetes get pod $OVNKUBE_CONTROL_PLANE_POD -o=jsonpath={.spec.nodeName}`
   echo "The Node of Pod $OVNKUBE_CONTROL_PLANE_POD is $NODE_NAME"
   #NODE_NAME=`oc get nodes | grep worker | awk '{print $1}'| sort -n -r | tail -1`
   OVNKUBE_NODE_POD=`oc -n openshift-ovn-kubernetes get pod -l app=ovnkube-node --field-selector spec.nodeName=$NODE_NAME, -ojsonpath='{..metadata.name}'`
   echo OVNKUBE_NODE_POD on node $NODE_NAME is $OVNKUBE_NODE_POD
   echo "Previous ACL is $ACL and Previous ACL is $MATCH_ACL " 
   NEWACL=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl --no-leader-only --columns=_uuid list acl | grep ^_uuid | wc -l'`;
   NEW_MATCH_ACL=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl --no-leader-only --columns=match list acl | grep -c ^match'`;
   for ((i=0;i<=15;i++))
   do
       NEWACL=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl --no-leader-only --columns=_uuid list acl | grep ^_uuid | wc -l'`;
       NEW_MATCH_ACL=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl --no-leader-only --columns=match list acl | grep -c ^match'`;
       if [[ $NEWACL -ne $ACL && $NEWACL -eq $NEW_MATCH_ACL ]];then
           export ACL=$NEWACL
           export MATCH_ACL=$NEW_MATCH_ACL
           break
       fi
       echo -n "."&&sleep 2
   done
   echo "New ACL After Creating BANP, ANP, NetPol, is $ACL" 
   echo "New Match ACL After Creating BANP, ANP, NetPol, is $MATCH_ACL"      
   echo "----------ACL----------";
   echo $ACL
   echo "----------match ACL----------";
   echo $MATCH_ACL
   echo "----------ACL find port_group by uuid----------";
   export PORT_GROUP_UUID=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl find port_group|grep _uuid|wc -l'`;
   echo $PORT_GROUP_UUID
   echo "----------ACL find address_set by uuid----------";
   export ADDRESS_SET_UUID=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl find address_set|grep _uuid|wc -l'`;
   echo $ADDRESS_SET_UUID
   echo "----------Logical Flow lflow-list----------";
   export LFLOW=`oc -n openshift-ovn-kubernetes exec -c sbdb $OVNKUBE_NODE_POD -- sh -c 'ovn-sbctl lflow-list |wc -l'`;
   echo $LFLOW
   echo "----------dump-flows br-int----------";
   export DUMP_FLOW_BR_INT=`oc -n openshift-ovn-kubernetes debug node/$NODE_NAME -q -- chroot /host ovs-ofctl -O OpenFlow13 dump-flows br-int |wc -l`;
   echo $DUMP_FLOW_BR_INT       
   echo "----------ACL find external_ids by uuid for each namespace----------";
   EGRESS_RULES_LIST=()
   for ns in `oc get ns |grep -E 'anp|cluster-density-v2'| awk '{print $1}'|tail -5`
   do
      EGRESS_RULES_NUMS=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=${ns}|wc -l"`;
      EGRESS_RULES_LIST+=(${ns}:${EGRESS_RULES_NUMS})
   done
   export EGRESS_RULES_NUMS_BY_NS=${EGRESS_RULES_LIST[*]}
   echo $EGRESS_RULES_NUMS_BY_NS | tr " " "\n"
}

function get_ovn_node_system_usage_info(){
   echo "----------------------TOP 10 Usage of Containers---------------------------"
   oc -n openshift-ovn-kubernetes adm top pods --containers| sort -n -r -k4 | head -10

   infraNodeNames=`oc get nodes |grep -E 'infra' |awk '{print $1}' | tr -s '\n' '|'`

   masterNodeNames=`oc get nodes |grep -E 'master' |awk '{print $1}' | tr -s '\n' '|'`
   masterNodeNames=${masterNodeNames:0:-1}
   echo "----------------------TOP Usage of Infra Node---------------------------"
   if [[ -n $infraNodeNames ]];then
      infraNodeNames=${infraNodeNames:0:-1}
      oc adm top nodes | grep -i -E "$infraNodeNames|NAME"  |sort -n -k5 
   else
      infraNodeNames="none"
   fi
   echo

   echo "----------------------TOP Usage of Master/ControlPlane Node---------------------------"
   oc adm top nodes | grep -i -E "$masterNodeNames|NAME" |sort -n -k5 
   echo

   echo "----------------------TOP 10 Usage of Worker Node---------------------------"
   oc adm top node | grep NAME
   oc adm top nodes | grep -i -E -v "$masterNodeNames|$infraNodeNames" | sort -k5 -nr | head -10
   echo "----------------------The Max 3 RAM Usage of Worker Node---------------------------"
   oc adm top node | grep NAME | awk '{print $1"\t\t\t\t\t"$4"\t"$5}'
   oc adm top nodes | grep -i -E -v "$masterNodeNames|$infraNodeNames|NAME" | sort -k5 -n | awk '{print $1"\t"$4"\t"$5}'| tail -3
   echo "----------------------The Max 3 CPU Usage of Worker Node---------------------------"
   oc adm top node | grep NAME | awk '{print $1"\t\t\t\t\t"$2"\t"$3}'
   oc adm top nodes | grep -i -E -v "$masterNodeNames|$infraNodeNames|NAME" | sort -k3 -n | awk '{print $1"\t"$2"\t"$3}'| tail -3
   echo "----------------------`date`-------------------------------"
   export MAX_MASTER_CPU=`oc adm top nodes | grep -i -E "$masterNodeNames|NAME" | sort -n -k3| tail -1| awk '{print $3"("$2")"}'`
   export MAX_MASTER_RAM=`oc adm top nodes | grep -i -E "$masterNodeNames|NAME" | sort -n -k5| tail -1| awk '{print $5"("$4")"}'`
     
   export MAX_WORKER_CPU=`oc adm top nodes | grep -i -E -v "$masterNodeNames|$infraNodeNames|NAME" | sort -n -k3| tail -1| awk '{print $3"("$2")"}'`
   export MAX_WORKER_RAM=`oc adm top nodes | grep -i -E -v "$masterNodeNames|$infraNodeNames|NAME" | sort -n -k5| tail -1| awk '{print $5"("$4")"}'`
   
   if oc -n openshift-ovn-kubernetes get pods |grep ovnkube-master; then
      getLegcyOVNInfo
   else
      getOVNICDBInfo
   fi
   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
   echo -e "Test Step,Create Time,Query Time, Max Master CPU,Max Master RAM,Max Worker CPU,Max Worker RAM,ACL,Match ACL,Port Group,Address Set,lflow-list,dump-flows br-int"
   echo $TEST_STEP,$CREATE_TIME,$QUERY_TIME,$MAX_MASTER_CPU,$MAX_MASTER_RAM,$MAX_WORKER_CPU,$MAX_WORKER_RAM,$ACL,$MATCH_ACL,$PORT_GROUP_UUID,$ADDRESS_SET_UUID,$LFLOW,$DUMP_FLOW_BR_INT | tee -a /tmp/system_resource_info.csv
   echo $EGRESS_RULES_NUMS_BY_NS| tr " " "\n"
   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
}

function getTotalCPUByLabel(){
 labelName=$1
 nodeNum=`oc get nodes -l${labelName} |grep -v NAME|wc -l `
 nodeName=`oc get nodes -l${labelName} |grep -v NAME| head -1 | awk '{print $1}'`
 cpuCoresPerNode=`oc get nodes ${nodeName} -ojsonpath={.status.capacity.cpu}`
 totalCPUCores=$(( $nodeNum * $cpuCoresPerNode ))
 echo $totalCPUCores
}

function getTotalCPUByLabel(){
 labelName=$1
 nodeNum=`oc get nodes -l${labelName} |grep -v NAME|wc -l `
 nodeName=`oc get nodes -l${labelName} |grep -v NAME| head -1 | awk '{print $1}'`
 cpuCoresPerNode=`oc get nodes ${nodeName} -ojsonpath={.status.capacity.cpu}`
 totalCPUCores=$(( $nodeNum * $cpuCoresPerNode ))
 echo $totalCPUCores
}

function createAutoscaler(){
totalCPUInfra=`getTotalCPUByLabel node-role.kubernetes.io/infra`
totalCPUWorkload=`getTotalCPUByLabel node-role.kubernetes.io/workload`
totalCPUWorker=`getTotalCPUByLabel node-role.kubernetes.io/worker`
totalCPUMaster=`getTotalCPUByLabel node-role.kubernetes.io/master`
totalCPUCores=$(( $totalCPUInfra + $totalCPUWorkload + $totalCPUWorker + $totalCPUMaster ))
echo totalCPUInfra is $totalCPUInfra
echo totalCPUWorkload is $totalCPUWorkload
echo totalCPUWorker is $totalCPUWorker
echo totalCPUMaster is $totalCPUMaster
echo totalCPUCores is $totalCPUCores
maxLimiteCPUCores=$(( $totalCPUCores + 160 ))
currentNodes=`oc get nodes |grep -v NAME|wc -l`
maxLinitedNodes=$(( $currentNodes + 10 ))
oc apply -f-<<EOF
apiVersion: "autoscaling.openshift.io/v1"
kind: "ClusterAutoscaler"
metadata:
  name: "default"
spec:
  balanceSimilarNodeGroups: true
  skipNodesWithLocalStorage: true
  logVerbosity: 4
  podPriorityThreshold: -10
  resourceLimits:
    maxNodesTotal: ${maxLinitedNodes}
  cores:
    min: ${totalCPUCores}
    max: ${maxLimiteCPUCores}
  logVerbosity: 4
  scaleDown:
    enabled: true
    delayAfterAdd: 10m
    delayAfterDelete: 5m
    delayAfterFailure: 30s
    unneededTime: 5m
    utilizationThreshold: "0.4"
EOF
machineSetName=`oc get machineset -A|grep worker | awk '{print $2}'|head -1`
currentReplicas=`oc -n openshift-machine-api get machineset $machineSetName -ojsonpath={.spec.replicas}`
maxReplicas=$(( $currentReplicas + 10 ))
oc apply -f-<<EOF
apiVersion: "autoscaling.openshift.io/v1beta1"
kind: "MachineAutoscaler"
metadata:
  name: "worker-autoscaling"
  namespace: "openshift-machine-api"
spec:
  minReplicas: ${currentReplicas}
  maxReplicas: ${maxReplicas}
  scaleTargetRef:
    apiVersion: machine.openshift.io/v1beta1
    kind: MachineSet
    name: ${machineSetName}
EOF
machineSetName=`oc get machineset -A|grep workload | awk '{print $2}'|head -1`
currentReplicas=`oc -n openshift-machine-api get machineset $machineSetName -ojsonpath={.spec.replicas}`
maxReplicas=$(( $currentReplicas + 10 ))
oc apply -f-<<EOF
apiVersion: "autoscaling.openshift.io/v1beta1"
kind: "MachineAutoscaler"
metadata:
  name: "workload-autoscaling"
  namespace: "openshift-machine-api"
spec:
  minReplicas: ${currentReplicas}
  maxReplicas: ${maxReplicas}
  scaleTargetRef:
    apiVersion: machine.openshift.io/v1beta1
    kind: MachineSet
    name: ${machineSetName}
EOF
}

create_ingress_controller(){
  
DEFAULT_INGRESS_CONTROLLER=`oc get nodes -lnode-role.kubernetes.io/worker |wc -l | tr -d ' '`
MAX_INGRESS_CONTROLLER=${MAX_INGRESS_CONTROLLER:=$DEFAULT_INGRESS_CONTROLLER}
echo "Creating $MAX_INGRESS_CONTROLLER ingress controller, the replicas is 4"
OCP_COMMON_DOMAIN_NAME=`oc -n openshift-ingress-operator get ingresscontroller default -ojsonpath={.status.domain}`
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650   -nodes -keyout tls.key -out tls.crt -subj "/CN=perfsale-qe.com"   -addext "subjectAltName=DNS:*.${OCP_COMMON_DOMAIN_NAME}"
oc --namespace openshift-ingress create secret tls customized-tls --cert=tls.crt --key=tls.key
INDEX=1

for routename in `oc get route -A | grep perfweb-ingress-route | awk '{print $3}' | tail -${MAX_INGRESS_CONTROLLER}`
do
  DOMAIN_NAME=$routename
oc apply -f-<<EOF
apiVersion: operator.openshift.io/v1
kind: IngressController
metadata:
  name: perfscale-qe-igr${INDEX}
  namespace: openshift-ingress-operator
spec:
  clientTLS:
    clientCA:
      name: ""
    clientCertificatePolicy: ""
  defaultCertificate:
    name: customized-tls
  domain: ${DOMAIN_NAME}
  endpointPublishingStrategy:
    type: Private
  httpCompression: {}
  httpEmptyRequestsPolicy: Respond
  httpErrorCodePages:
    name: ""
  namespaceSelector:
    matchLabels:
      kube-burner-job: cluster-density-v2
  replicas: 2
  routeAdmission:
    wildcardPolicy: WildcardsDisallowed
  routeSelector:
    matchLabels:
      router: internal
  tlsSecurityProfile:
    type: Intermediate
  tuningOptions: {}
EOF
INDEX=$(( $INDEX + 1 ))
done
}

function create_customized_workload(){
    CUSTOMIZED_WORKLOAD_FILE=${CUSTOMIZED_WORKLOAD_FILE:="/tmp/customized_workload.yaml"}  
    CUSTOMIZED_ITERATIONS=${CUSTOMIZED_ITERATIONS:="1"}
    NAMESPACE=$1
    WORKLOAD_TYPE=$2
    WORKLOAD_NAME=${NAMESPACE}-${WORKLOAD_TYPE}
    
cat >${CUSTOMIZED_WORKLOAD_FILE}<<EOF
---
global:
  gc: {{.GC}}
  gcMetrics: {{.GC_METRICS}}
  measurements:
    - name: podLatency
      thresholds:
        - conditionType: Ready
          metric: P99
          threshold: {{.POD_READY_THRESHOLD}}
{{ if eq .SVC_LATENCY "true" }}
    - name: serviceLatency
      svcTimeout: 10s
{{ end }}
metricsEndpoints:
{{ if .ES_SERVER }}
  - metrics: [{{.METRICS}}]
    alerts: [{{.ALERTS}}]
    indexer:
      esServers: ["{{.ES_SERVER}}"]
      insecureSkipVerify: true
      defaultIndex: {{.ES_INDEX}}
      type: opensearch
{{ end }}
{{ if eq .LOCAL_INDEXING "true" }}
  - metrics: [{{.METRICS}}]
    alerts: [{{.ALERTS}}]
    indexer:
      type: local
      metricsDirectory: collected-metrics-{{.UUID}}
{{ end }}
jobs:
  - name: ${WORKLOAD_NAME}  
    namespace: ${NAMESPACE}
    jobIterations: ${CUSTOMIZED_ITERATIONS}
    qps: {{.QPS}}
    burst: {{.BURST}}
    namespacedIterations: true
    podWait: false
    waitWhenFinished: true
    preLoadImages: true
    preLoadPeriod: 15s
    churn: {{.CHURN}}
    churnCycles: {{.CHURN_CYCLES}}
    churnDuration: {{.CHURN_DURATION}}
    churnPercent: {{.CHURN_PERCENT}}
    churnDelay: {{.CHURN_DELAY}}
    churnDeletionStrategy: {{.CHURN_DELETION_STRATEGY}}
    namespaceLabels:
      security.openshift.io/scc.podSecurityLabelSync: false
      pod-security.kubernetes.io/enforce: privileged
      pod-security.kubernetes.io/audit: privileged
      pod-security.kubernetes.io/warn: privileged
      k8s.ovn.org/primary-user-defined-network: "" 
      anplabel: ${NAMESPACE}
    objects:
EOF

}

function append_customized_workload_without_inputvar(){
     CUSTOMIZED_WORKLOAD_FILE=${CUSTOMIZED_WORKLOAD_FILE:="/tmp/customized_workload.yaml"}
     CUSTOMIZED_CRD_YAML=$1
     OBJ_REPLICAS=${OBJ_REPLICAS:="1"}
     echo -e "\n      - objectTemplate: ${CUSTOMIZED_CRD_YAML}\n        replicas: ${OBJ_REPLICAS}">>${CUSTOMIZED_WORKLOAD_FILE}
}

function append_customized_workload4Pods(){
     CUSTOMIZED_WORKLOAD_FILE=${CUSTOMIZED_WORKLOAD_FILE:="/tmp/customized_workload.yaml"}
     NAMESPACE=$1
     CUSTOMIZED_CRD_YAML=$2

     OBJ_REPLICAS=${OBJ_REPLICAS:="1"}
     echo -e "\n      - objectTemplate: ${CUSTOMIZED_CRD_YAML}\n        replicas: ${OBJ_REPLICAS}\n        inputVars:\n          podReplicas: ${POD_REPLICAS}\n          nodeSelector: \"{{.POD_NODE_SELECTOR}}\"\n          anplabel: \"${NAMESPACE}\"">>${CUSTOMIZED_WORKLOAD_FILE}
}

function append_customized_workload4Service(){
     CUSTOMIZED_WORKLOAD_FILE=${CUSTOMIZED_WORKLOAD_FILE:="/tmp/customized_workload.yaml"}
     NAMESPACE=$1
     CUSTOMIZED_CRD_YAML=$2
     OBJ_REPLICAS=${OBJ_REPLICAS:="1"}
     echo -e "\n      - objectTemplate: ${CUSTOMIZED_CRD_YAML}\n        replicas: ${OBJ_REPLICAS}\n        inputVars:\n          anplabel: \"${NAMESPACE}\"">>${CUSTOMIZED_WORKLOAD_FILE}
}


function scale_out_down_nodes(){
  machinesetName=`oc -n openshift-machine-api get machineset |grep -v -E 'infra|workload|NAME'|awk '{print $1}'| head -1`
  currentNodeNum=`oc -n openshift-machine-api get machineset $machinesetName -ojsonpath={.spec.replicas}`
  expecteNodeNum=$(( $currentNodeNum + 5 ))
  echo "scaling out worker node to $expecteNodeNum"

              
  echo "Save old node name and ovn pod list to old-node-ovn-pods.lst"
  awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
  oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
  oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst  
  echo    "#############   ocp-node-ovn-pods-old.lst  #############" 
  awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
  cat /tmp/ocp-node-ovn-pods-old.lst
  awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

  oc -n openshift-machine-api scale machineset $machinesetName --replicas=$expecteNodeNum
  sleep 180
  INIT=1
  MAX_RETRY=180
  while true;
  do
      WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name worker`
      if [[ $WORKER_MCP_STATUS == "true"  ]];then
          echo "worker nodes scale to $expecteNodeNum"
          break
      fi
      INIT=$(( $INIT + 1 ))
      if [[ $INIT -ge $MAX_RETRY ]];then
      echo "The worker nodes isn't scale out in limited time"
      exit 1
      fi
      sleep 30
  done

  oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
  oc get nodes |grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
  echo "New worker node and ovn pods when scaling out worker node"
  awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
  cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u 
  echo 
  cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u | tr -s "\n" "|"
  echo

  echo "scaling down worker node to $currentNodeNum"
  oc -n openshift-machine-api scale machineset $machinesetName --replicas=$currentNodeNum
  sleep 180
  INIT=1
  MAX_RETRY=30
  while true;
  do
      WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name worker`
      if [[ $WORKER_MCP_STATUS == "true"  ]];then
          echo "worker nodes scale to $currentNodeNum"
          break
      fi
      INIT=$(( $INIT + 1 ))
      if [[ $INIT -ge $MAX_RETRY ]];then
      echo "The worker nodes isn't scale down in limited time"
      exit 1
      fi
      sleep 30
  done
}

function recycle_worker_node(){
        
    IF_RECYCLE_NODE=${IF_RECYCLE_NODE:="false"}
    if [[ $IF_RECYCLE_NODE = "true" ]];then
         awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
         echo "Gracefully reboot worker node"    
         export TEST_STEP="Gracefully reboot worker node"
         export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`               
         for workerNode in `oc get nodes |grep worker | awk '{print $1}'|head -5`
         do
         	  echo  oc -n openshift-ovn-kubernetes debug node/$workerNode -q -- chroot /host reboot
         	  oc -n openshift-ovn-kubernetes debug node/$workerNode -q -- chroot /host reboot&
             sleep 5
         done
         sleep 300
         for((i=0;i<=600;i++))
         do
             WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name worker`
             if [[ $WORKER_MCP_STATUS == "true" ]];then
                    echo The worker mcp is ready
                        break
             fi
             echo -n "."&&sleep 10;
         done
         sleep 300
         export TEST_STEP="After reboot nodes when OVN CNI migration complete"
         export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
         export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
         get_ovn_node_system_usage_info
    fi 
}

function restartOVNPODs(){
      echo "Save old node name and ovn pod list to old-node-ovn-pods.lst when ovn pod restart"
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
      oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
      oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst
      cat /tmp/ocp-node-ovn-pods-old.lst
      echo

      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
      echo "Restart OVN Pods"
      OVN_NODE_POD_NAMES=`oc -n openshift-ovn-kubernetes  get pods |grep -v -i -E 'ovnkube-control-plane|NAME' | awk '{print $1}'| tail -5`
      for ovn_node_pod in $OVN_NODE_POD_NAMES
      do  
           echo restart pod $ovn_node_pod
           oc -n openshift-ovn-kubernetes delete pod $ovn_node_pod
      done
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
      export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
      get_ovn_node_system_usage_info
      sleep 30

      oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
      oc get nodes |grep -v -i NAME| awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
      echo "New ovn pods after restart OVN Node Pods"
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
      cat /tmp/ocp-node-ovn-pods-*.lst |sort -r| uniq -u
      echo 
      cat /tmp/ocp-node-ovn-pods-*.lst |sort -r| uniq -u| tr -s "\n" "|"
      echo
}

function networkPolicyInitSyncDurationCheck(){
   #Check If existing pod is running
   UUID=${UUID:=""}
   WAIT_OVN_DB_SYNC_TIME=${WAIT_OVN_DB_SYNC_TIME:=""}
  
   if ! oc get ns |grep -w zero-trust-ns >/dev/null;
   then
      oc create ns zero-trust-ns;
   fi  


   export TEST_STEP="Creating deny-all netpol in zero-trust-ns"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
   oc -n zero-trust-ns apply -f networkpolicy-deny-all.yml
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`      
   get_ovn_node_system_usage_info   

   waiting_for_during_each_phase "networkPolicyInitSyncDurationCheck" 300 "Wait for more time to check if the deny-all networkpolicy is synced"

   #Creating new netpol/pod to check if the new networkpolicy is synced in time
   export TEST_STEP="Creating 3 networkpolicy/pods in zero-trust-ns"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`

   export CUSTOMIZED_ITERATIONS=1
   export POD_REPLICAS=10
   CUSTOMIZED_WORKLOAD_FILE=customized-workload.yml
   create_customized_workload zero-trust-ns workload
   append_customized_workload_without_inputvar networkpolicy-allowdns.yml
   append_customized_workload_without_inputvar networkpolicy-egress-within-same-ns.yml 
   echo -e "        inputVars:\n          selected_pod_type: \"perfapp\"\n          ingress_pod_type: \"perfdb\"\n          ns_label: \"anplabel\"\n          ns_label_value: \"zero-trust-ns\"\n          pod_label: \"type\"\n          pod_label_value: perfdb">> $CUSTOMIZED_WORKLOAD_FILE   
   append_customized_workload_without_inputvar networkpolicy-ingress-within-same-ns.yml
   echo -e "        inputVars:\n          selected_pod_type: \"perfdb\"\n          ingress_pod_type: \"perfapp\"\n          anplabel: \"zero-trust-ns\"">> $CUSTOMIZED_WORKLOAD_FILE
   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
   append_customized_workload4Pods zero-trust-ns postgres-deployment.yml
   append_customized_workload4Service zero-trust-ns postgres-service.yml
   append_customized_workload4Pods zero-trust-ns perfapp-deployment.yml  
   cat $CUSTOMIZED_WORKLOAD_FILE
   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
   echo  ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
   ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml

   #oc -n zero-trust-ns wait --timeout=120s --for=condition=Ready pod -l app=ingress-nodeip-request-app     
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`   
   get_ovn_node_system_usage_info
   echo "----------------------`date`-------------------------------"
}

function printYAMLFile(){
    YAMLFILE=$1
    echo "#########################################################################"
    echo Apply $YAMLFILE to OCP Cluster
    echo "-------------------------------------------------------------------------"
    cat  $YAMLFILE
    echo
    echo "-------------------------------------------------------------------------"
    echo
    KIND_NAME=`grep "kind:" $YAMLFILE | awk '{print $2}'| uniq | tr -d ' '`
    ANP_NAME=`grep -A2 "metadata:" $YAMLFILE | grep "name:" | awk '{print $2}'| tr "\n" " "`
    echo Creating $KIND_NAME: $ANP_NAME
    if [[ -z $ANP_NAME ]];then
        echo no ANP_NAME was found
    else
	if [[ $KIND_NAME == "BaselineAdminNetworkPolicy" ]];then
           oc get banp | grep -w $ANP_NAME>/dev/null
           RC=$?
      	   if [[ $RC -eq 0 ]]; then
             oc get banp $ANP_NAME -oyaml |grep SetupFailed >/dev/null
             if [[ $? -eq 0 ]];then
                echo "BANP setup failed, please check"
                oc get banp default -ojsonpath={.status}| jq
                exit 1
             fi
	   fi
	else
             for name in $ANP_NAME
	     do
                 oc get anp | grep -w $name>/dev/null
                 RC=$?
                 if [[ $RC -eq 0 ]]; then
                     oc get anp $name -oyaml |grep SetupFailed >/dev/null
                     if [[ $? -eq 0 ]]; then
                          echo "ANP setup failed, please check"
                          oc get anp $name -ojsonpath={.status}| jq
                          exit 1
                     fi
		 else
			 echo "$KIND_NAME $name not found and please check if yaml file is correct"
			 exit 1
                 fi
	     done
	fi
    fi
}

function check_traffic_between_anp_ns_groups(){
    
    SOURCE_NS=$1
    TARGET_NS=$2
    PORT_NUMBER=$3
    EXPECTED_RESULT=$4

    if [[ -z $TARGET_NS || -z $SOURCE_NS ]];then
            echo please specify TARGET_NS_FILTER or SOURCE_NS_FILTER
            exit 1
    fi

    TARGET_NS=`oc get ns |grep -w $TARGET_NS | awk '{print $1}'|head -1`
    if [[ -z $TARGET_NS ]];then
            echo "No TARGET_NS was found"
            exit 1
    fi

    SOURCE_NS=`oc get ns |grep -w $SOURCE_NS | awk '{print $1}'| head -1`
    if [[ -z $SOURCE_NS ]];then
            echo "No SOURCE_NS was found"
            exit 1
    fi

    SOURCE_POD=`oc -n $SOURCE_NS get pods|grep reqegress | head -1 | awk '{print $1}'`
    #echo "find SOURCE_POD $SOURCE_POD in $SOURCE_NS inside check_traffic_between_anp_ns_groups "
    if [[ -z $SOURCE_POD ]];then
            echo "No SOURCE_POD was found"
            exit 1
    fi
    # echo SOURCE_NS is $SOURCE_NS
    # echo SOURCE_POD is $SOURCE_POD
    for ns in $TARGET_NS
    do
            if [[ $PORT_NUMBER -eq 8080 ]];then
                 #POD_IPs=`oc -n $ns get pods -owide |grep -w app | awk '{print $6}'| head -3`
                 POD_IPs=`oc -n $ns get pods -ltrafficapp=perfapp -ojsonpath='{.items[*].status.podIP}' | cut -d' ' -f 1-3`
            elif [[ $PORT_NUMBER -eq 5432 ]];then
                 #POD_IPs=`oc -n $ns get pods -owide |grep -w db | awk '{print $6}'| head -3`
                 POD_IPs=`oc -n $ns get pods -ltrafficapp=perfdb -ojsonpath='{.items[*].status.podIP}' | cut -d' ' -f 1-3`
            fi
            #Get Pods IP via service port
            for pod_ip in $POD_IPs
            do
                echo
                echo oc -n $SOURCE_NS exec -i $SOURCE_POD -- nc -vz $pod_ip $PORT_NUMBER -w 5
                echo -----------------------------------------------------------------------
                retry=0
                oc -n $SOURCE_NS exec -i $SOURCE_POD -- nc -vz $pod_ip $PORT_NUMBER -w 5
             
                if [[ $? -eq 0 ]];then
                    echo "The traffic between $SOURCE_NS and $ns is accessiable"
                    RESULT="true"
                else
                    echo "The traffic between $SOURCE_NS and $ns is denied"
                    #Retry once again
                    oc -n $SOURCE_NS exec -i $SOURCE_POD -- nc -vz $pod_ip $PORT_NUMBER -w 5
                    if [[ $? -eq 0 ]];then
                       RESULT="true"
                    else
                       RESULT="false"
                    fi
                fi
                if [[ $RESULT == $EXPECTED_RESULT ]];then
                     echo This is expected result.
                else
                     echo "The is unexpected result, please check."
                     exit 1
                fi
            done
    done
}

function format_Output_ANP_BANP_Source2Target(){
    
    SOURCE_NS=$1
    TARGET_NS=$2
    PORT_NUMBER=$3
    EXPECTED_RESULT=$4

    if [[ $EXPECTED_RESULT == "false" ]];then
        DENY_OR_ALLOW=Deny
    elif [[ $EXPECTED_RESULT == "true" ]];then
        DENY_OR_ALLOW=Allow
    else
        echo "Invalid Parameter for format_Output_ANP_BANP"
        exit 1
    fi
    
    if [[ $NO_VERIFY_ANP == "true" ]];then
        echo "No need to verify the traffic between $SOURCE_NS and $TARGET_NS zones"
        return
    fi

    echo "#########################################################################"
    echo "#        ${DENY_OR_ALLOW} traffic $SOURCE_NS to $TARGET_NS zones     #"
    echo "#########################################################################"
    echo "Verify the traffic between $SOURCE_NS and $TARGET_NS zones"
    check_traffic_between_anp_ns_groups $SOURCE_NS $TARGET_NS $PORT_NUMBER $EXPECTED_RESULT
}

function format_Output_ANP_BANP_Target2Source(){
    SOURCE_NS=$1
    TARGET_NS=$2
    PORT_NUMBER=$3
    EXPECTED_RESULT=$4

    if [[ $EXPECTED_RESULT == "false" ]];then
        DENY_OR_ALLOW=Deny
    elif [[ $EXPECTED_RESULT == "true" ]];then
        DENY_OR_ALLOW=Allow
    else
        echo "Invalid Parameter for format_Output_ANP_BANP"
        exit 1
    fi   

    if [[ $NO_VERIFY_ANP == "true" ]];then
        echo "No need to verify the traffic between $TARGET_NS and $SOURCE zones"
        return
    fi

    echo "Verify the traffic between $TARGET_NS and $SOURCE zones"
    echo "#########################################################################"
    echo "#      ${DENY_OR_ALLOW} traffic $TARGET_NS to $SOURCE_NS zones    #"
    echo "#########################################################################"  
    check_traffic_between_anp_ns_groups $TARGET_NS $SOURCE_NS $PORT_NUMBER $EXPECTED_RESULT
}

function format_Output_ANP_BANP_Source2Host(){
    
    SOURCE_NS=$1
    NODE_LABEL=$2
    PORT_NUMBER=$3
    EXPECTED_RESULT=$4

    if [[ $EXPECTED_RESULT == "false" ]];then
        DENY_OR_ALLOW=Deny
    elif [[ $EXPECTED_RESULT == "true" ]];then
        DENY_OR_ALLOW=Allow
    else
        echo "Invalid Parameter for format_Output_ANP_BANP"
        exit 1
    fi

    if [[ $NO_VERIFY_ANP == "true" ]];then
        echo "No need to verify the traffic between $SOURCE_NS and target node host ip"
        return
    fi

    echo NODE_LABEL is $NODE_LABEL inside format_Output_ANP_BANP_Source2Host
    echo "#########################################################################"
    echo "#        ${DENY_OR_ALLOW} traffic $SOURCE_NS to $PORT_NUMBER of node host ip         #"
    echo "#########################################################################"
    echo "Verify the traffic between $SOURCE_NS and target node host ip"
    check_traffic_to_labeled_node_host $SOURCE_NS "$NODE_LABEL" $PORT_NUMBER $EXPECTED_RESULT
}

function check_traffic_to_labeled_node_host(){
    SOURCE_NS_PREFIX=$1
    NODE_LABEL=$2
    PORT_NUMBER=$3
    EXPECTED_RESULT=$4
    
    if [[ -z $SOURCE_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX or SOURCE_NS_PREFIX
            exit 1
    fi

    SOURCE_NS=`oc get ns |grep -w $SOURCE_NS_PREFIX | awk '{print $1}'| head -1`
    if [[ -z $SOURCE_NS ]];then
            echo "No SOURCE_NS $SOURCE_NS was found"
            exit 1
    fi

    echo NODE_LABEL is $NODE_LABEL inside check_traffic_to_labeled_node_host
    for ns in `oc get ns |grep -w $SOURCE_NS_PREFIX | awk '{print $1}'`
    do
         echo "check the egress pod in $ns inside check_traffic_to_labeled_node_host"
         SOURCE_POD=`oc -n $ns get pods|grep reqegress | head -1 | awk '{print $1}'`
         if [[ -z $SOURCE_POD ]];then
            echo "No SOURCE_POD was found"
            exit 1
         fi
         #echo SOURCE_NS is $ns
         #echo SOURCE_POD is $SOURCE_POD
         for ipaddr in `oc get nodes -l"${NODE_LABEL}" -ojsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}' |tail -3`
         do
             echo
             echo oc -n $ns exec -i $SOURCE_POD -- nc -vz $ipaddr $PORT_NUMBER -w 5
             echo -----------------------------------------------------------------------
             oc -n $ns exec -i $SOURCE_POD -- nc -vz $ipaddr $PORT_NUMBER -w 5
             if [[ $? -eq 0 ]];then
                 echo "The traffic between $ns and $ipaddr with port $PORT_NUMBER is accessiable"
                 RESULT="true"
             else
                 echo "The traffic between $ns and $ipaddr with port $PORT_NUMBER is denied"
                 RESULT="false"
             fi
             if [[ $RESULT == $EXPECTED_RESULT ]];then
                  echo This is expected result.
             else
                  echo "The is unexpected result, please check."
                  exit 1
             fi
         done    
    done
}

function create_pod_selector_anp_and_verify_traffic_between_ns_groups(){

    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-restricted"
    export TEST_STEP="Creating 14 POD Selector ANP Egress/Ingress Policy[Min]."
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 14 POD Selector ANP Egress/Ingress Policy[Min]"      
    oc apply -f 02_anp-no-traffic-test-restricted-p39.yaml   
    printYAMLFile 02_anp-no-traffic-test-restricted-p39.yaml
 
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-restricted"      
    oc apply -f 03_anp-no-traffic-unknown-restricted-p38.yaml
    printYAMLFile 03_anp-no-traffic-unknown-restricted-p38.yaml

    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false    

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    echo "Creating 1 POD Selector ANP of No traffic between test and unknown."     
    oc apply -f 04_anp-no-traffic-test-unknown-p37.yaml
    printYAMLFile 04_anp-no-traffic-test-unknown-p37.yaml
 
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false   

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    echo "Creating 1 POD Selector ANP of allowing ingress only between test and unknown."     
    oc apply -f 05_anp-allow-ingress-only-test-unknown-p36.yaml
    printYAMLFile 05_anp-allow-ingress-only-test-unknown-p36.yaml
 
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true   

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    echo "Creating 1 POD Selector ANP of allowing egress only between test and unknown."     
    oc apply -f 06_anp-allow-egress-only-test-unknown-p35.yaml
    printYAMLFile 06_anp-allow-egress-only-test-unknown-p35.yaml

    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
  
    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    echo "Creating 1 POD Selector ANP of no traffic between unknown and open."      
    oc apply -f 07_anp-no-traffic-unknown-open-p34.yaml
    printYAMLFile 07_anp-no-traffic-unknown-open-p34.yaml
  
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    echo "Creating 1 POD Selector ANP of ingress only between unknown and open."    
    oc apply -f 08_anp-allow-ingress-only-unknown-open-p33.yaml
    printYAMLFile 08_anp-allow-ingress-only-unknown-open-p33.yaml

    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
  
    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    echo "Creating 1 POD Selector ANP of egress only between unknown and open."     
    oc apply -f 09_anp-allow-egress-only-unknown-open-p32.yaml
    printYAMLFile 09_anp-allow-egress-only-unknown-open-p32.yaml
 
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
  
    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    echo "Creating 1 POD Selector ANP of no traffic between open and test."      
    oc apply -f 10_anp-no-traffic-open-test-p31.yaml
    printYAMLFile 10_anp-no-traffic-open-test-p31.yaml
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    echo "Creating 1 POD Selector ANP of allow ingress between open and test."    
    oc apply -f 11_anp-allow-ingress-only-open-test-p30.yaml
    printYAMLFile 11_anp-allow-ingress-only-open-test-p30.yaml
 
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
  
    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"

    echo "Creating 1 POD Selector ANP of allow egress between open and test."       
    oc apply -f 12_anp-allow-egress-only-open-test-p29.yaml
    printYAMLFile 12_anp-allow-egress-only-open-test-p29.yaml
   
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    echo "Creating 1 POD Selector ANP of allow all traffic between open and test."     
    oc apply -f 13_anp-allow-all-traffic-open-test-p28.yaml
    printYAMLFile 13_anp-allow-all-traffic-open-test-p28.yaml
 
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    echo "Creating 1 POD Selector ANP of allow all traffic between unknown and test."       
    oc apply -f 14_anp-allow-all-traffic-unknown-open-p27.yaml
    printYAMLFile 14_anp-allow-all-traffic-unknown-open-p27.yaml
   
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
  
    echo "Creating 1 POD Selector ANP of allow all traffic between test and unknown."     
    oc apply -f 15_anp-allow-all-traffic-test-unknown-p26.yaml
    printYAMLFile 15_anp-allow-all-traffic-test-unknown-p26.yaml
   
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
    get_ovn_node_system_usage_info
}


function generate_cidr_selector_anp_multipolicy_with_multi_rules_multi_ips_bytenant(){
    #Create multiple anp
    #Each ANP contains multi rules
    #25 IPs per rule 
    SOURCE_NS_PREFIX=$1
    TARGET_NS_PREFIX=$2
    TOTAL_NS_BY_TA=${TOTAL_NS_BY_TA:=5}
    TOTAL_IP_BLOCK_NUM_BY_RULE=${TOTAL_IP_BLOCK_NUM_BY_RULE:=5}    
    PRIORITY=0 #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=/tmp

    if [[ -z $TARGET_NS_PREFIX || -z $SOURCE_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX $TARGET_NS_PREFIX or SOURCE_NS_PREFIX $SOURCE_NS_PREFIX 
            exit 1
    fi

    SOURCE_NS=`oc get ns |grep -w $SOURCE_NS_PREFIX | awk '{print $1}'`
    if [[ -z $SOURCE_NS ]];then
            echo "No SOURCE_NS_PREFIX $SOURCE_NS_PREFIX was found"
            exit 1
    fi

    >${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst
    NS_INIT=0
    TENANT_ID=0

    #NODE_INDEX=1
    for sns in $SOURCE_NS
    do      
            tns=`echo $sns | sed "s/${SOURCE_NS_PREFIX}/${TARGET_NS_PREFIX}/"`
            echo $sns $tns>>${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst
            # 4 ns per tenant
            IF_NEW_TENANT=$(( $NS_INIT % $TOTAL_NS_BY_TA ))
            TENANT_STEP=$(( $NS_INIT / $TOTAL_NS_BY_TA ))
            if [[ $IF_NEW_TENANT -eq 0 ]];then
                  TENANT_ID=$(( $TENANT_ID + 1 ))
                  PRIORITY=$(( $PRIORITY + 1 ))
                  echo PRIORITY is $PRIORITY
                  APP_POD_INIT=0
                  DB_POD_INIT=0
                  APP_RULE_INDEX=0
                  DB_RULE_INDEX=0
                  if [[ $PRIORITY -gt 99 ]];then
                       #reset PRIORITY to 1
                       PRIORITY=1
                  fi
            fi

            if [[ $IF_NEW_TENANT -eq 0 ]];then                   
cat>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-cidr-anp-open-network-tenant${TENANT_ID}-p${PRIORITY}
spec:
  priority: ${PRIORITY}
  subject:
    namespaces:
      matchLabels:
        customer_tenat: tenant${TENANT_ID}
  ingress:
  - name: "all-ingress-from-same-tenant"  
    action: Allow   # Allows connection 
    from:
    - namespaces:
        # namespaceSelector:
        matchLabels:
          customer_tenat: tenant${TENANT_ID}    
  egress:
  - name: "pass-egress-to-cluster-network"
    action: "Pass"
    ports:
      - portNumber:
          port: 9093
          protocol: TCP
      - portNumber:
          port: 9094
          protocol: TCP    
    to:
    - networks:
      - 10.128.0.0/14      
EOF
            fi            
            oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
            echo oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
            oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite
            echo oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite

            if [[ -z $tns ]];then
                 echo "No target ns was found inside generate_cidr_selector_anp_multipolicy_with_multi_rules_multi_ips_bytenant, please check"
            fi             

            TOTAL_APP_POD_NUM=$(oc -n $tns get pods -owide |grep -w app | wc -l)
            TOTAL_DB_POD_NUM=$(oc -n $tns get pods -owide |grep -w db | wc -l)
            if [[ $TOTAL_APP_POD_NUM -ne $TOTAL_DB_POD_NUM ]];then
                 echo TOTAL_APP_POD_NUM is $TOTAL_APP_POD_NUM TOTAL_DB_POD_NUM is $TOTAL_DB_POD_NUM
                 echo "Make sure perfapp pod and db pod with same replicas"
                 exit 1
            fi

            for podName in `oc -n $tns get pods -oname |grep -w -E 'app|db'`
            do
                 podType=`oc -n $tns get $podName -ojsonpath='{.metadata.labels.trafficapp}'`
                 if [[ $podType == "perfapp" ]];then
                     APP_POD_IP=`oc -n $tns get $podName -ojsonpath='{.status.podIP}'`
                     echo ===================================
                     echo ------------------------------------
                     echo  APP_POD_IP is $APP_POD_IP                     
                     echo  APP_POD_INIT is $APP_POD_INIT
                     echo ------------------------------------                     
                     IF_NEW_APP_RULE=$(( $APP_POD_INIT % $TOTAL_IP_BLOCK_NUM_BY_RULE ))
                     echo ------------------------------------
                     echo  IF_NEW_APP_RULE is $IF_NEW_APP_RULE 
                     echo ------------------------------------
                     if [[ $IF_NEW_APP_RULE -eq 0 ]];then
                        echo APP_RULE_INDEX is $APP_RULE_INDEX
                        APP_RULE_INDEX=$(( $APP_RULE_INDEX + 1 )) 
                        echo -e "  - name: \"allow-egress-to-anp-open-network-${APP_RULE_INDEX}\"\n    action: \"Allow\"\n    ports:\n      - portNumber:\n          port: 8080\n          protocol: TCP\n      - portRange:\n          start: 9201\n          end: 9205\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                   
                     fi

                     sed -i "/allow-egress-to-anp-open-network-${APP_RULE_INDEX}/{n;n;n;n;n;n;n;n;n;n;n;s/$/\n      - ${APP_POD_IP}\/32/;}" ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                 
                     APP_POD_INIT=$(( $APP_POD_INIT + 1 ))
                 elif [[ $podType == "perfdb" ]];then
                     DB_POD_IP=`oc -n $tns get $podName -ojsonpath='{.status.podIP}'`
                    
                     echo ===================================                    
                     echo ------------------------------------
                     echo  DB_POD_IP is $DB_POD_IP
                     echo  DB_POD_INIT is $DB_POD_INIT
                     echo ------------------------------------
                     IF_NEW_DB_RULE=$(( $DB_POD_INIT % $TOTAL_IP_BLOCK_NUM_BY_RULE ))
                     echo ------------------------------------
                     echo  IF_NEW_DB_RULE is $IF_NEW_DB_RULE 
                     echo ------------------------------------
                     if [[ $IF_NEW_DB_RULE -eq 0 ]];then
                        echo DB_RULE_INDEX is $DB_RULE_INDEX
                        DB_RULE_INDEX=$(( $DB_RULE_INDEX + 1 ))

                        echo -e "  - name: \"deny-egress-to-anp-open-network-${DB_RULE_INDEX}\"\n    action: \"Deny\"\n    ports:\n      - portNumber:\n          port: 5432\n          protocol: TCP\n      - portNumber:\n          port: 60000\n          protocol: TCP\n      - portNumber:\n          port: 9099\n          protocol: TCP\n      - portNumber:\n          port: 9393\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     fi

                     sed -i "/deny-egress-to-anp-open-network-${DB_RULE_INDEX}/{n;n;n;n;n;n;n;n;n;n;n;n;n;n;n;n;s/$/\n      - ${DB_POD_IP}\/32/;}" ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
              
                     DB_POD_INIT=$(( $DB_POD_INIT + 1 ))
                 else
                    echo "Invalid Pod Type ..."
                    exit 1
                 fi
                
            done
            NS_INIT=$(( $NS_INIT + 1 ))
    done

    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done

    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
}

function check_traffic_to_internet(){
    SOURCE_NS_PREFIX=$1
    EXPECTED_RESULT=$2

    if [[ $NO_VERIFY_ANP == "true" ]];then
        echo "No need to verify the traffic between $SOURCE_NS_PREFIX and internet"
        return
    fi

    if [[ -z $SOURCE_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX or SOURCE_NS_PREFIX
            exit 1
    fi

    SOURCE_NS=`oc get ns |grep -w $SOURCE_NS_PREFIX | awk '{print $1}'| head -1`
    if [[ -z $SOURCE_NS ]];then
            echo "No SOURCE_NS $SOURCE_NS was found"
            exit 1
    fi
 
    SOURCE_POD=`oc -n $SOURCE_NS get pods|grep reqegress | head -1 | awk '{print $1}'`
    if [[ -z $SOURCE_POD ]];then
            echo "No SOURCE_POD was found inside check_traffic_to_internet"
            exit 1
    fi
    
    for ipaddr in 8.8.8.8 1.1.1.1
    do
        oc -n $SOURCE_NS exec -i $SOURCE_POD -- ping -c2 $ipaddr    
        if [[ $? -eq 0 ]];then
            echo "The traffic between $SOURCE_NS_PREFIX and $ipaddr is accessiable"
            RESULT="true"
        else
            echo "The traffic between $SOURCE_NS_PREFIX and $ipaddr is denied"
            RESULT="false"
        fi
        if [[ $RESULT == $EXPECTED_RESULT ]];then
             echo This is expected result.
        else
             echo "The is unexpected result, please check."
             exit 1
        fi
    done    
}

function label_node_with_label_allow_deny_egress(){

     IF_LABEL_IN_ORDER=${IF_LABEL_IN_ORDER:="false"}
 
     TOTAL_NODES=`oc get nodes -lnode-role.kubernetes.io/worker= -oname |wc -l`
     if [[ $TOTAL_NODES -ge 3 && $TOTAL_NODES -le 20 ]];then
          KEEP_WORKER=1
     elif [[ $TOTAL_NODES -gt 30 ]];then
          KEEP_WORKER=10
     elif [[ $TOTAL_NODES -lt 3 ]];then
         echo "To run the test case, you have run it on OCP with more than 3 worker node"
         exit 1
     fi
     
     TOTAL_LABEL_NODES=$(( $TOTAL_NODES - $KEEP_WORKER ))
     LABEL_NUM=$(( $TOTAL_LABEL_NODES / 2 ))
     if [[ $IF_LABEL_IN_ORDER == "false" ]];then
          for node in `oc get nodes -lnode-role.kubernetes.io/worker= -oname |head -${LABEL_NUM}`
          do
              echo "label worker node $node as allow-egress=true"
              oc label $node node-role.kubernetes.io/allow-egress=true --overwrite
          done
          for node in `oc get nodes -lnode-role.kubernetes.io/worker= -oname |tail -${LABEL_NUM}`
          do
              echo "label worker node $node as deny-egress=true"
              oc label $node node-role.kubernetes.io/deny-egress=true --overwrite
          done
     elif [[ $IF_LABEL_IN_ORDER == "true" ]];then
         NODE_INDEX=1
         for node in `oc get nodes -lnode-role.kubernetes.io/worker= -oname |head -${LABEL_NUM}`
          do      
              echo label worker node $node as allow-egress="n$NODE_INDEX"
              oc label $node node-role.kubernetes.io/allow-egress="n$NODE_INDEX" --overwrite
              NODE_INDEX=$(( $NODE_INDEX + 1 ))
          done
          NODE_INDEX=1
          for node in `oc get nodes -lnode-role.kubernetes.io/worker= -oname |tail -${LABEL_NUM}`
          do
              echo label worker node $node as deny-egress="n$NODE_INDEX"
              oc label $node node-role.kubernetes.io/deny-egress="n$NODE_INDEX" --overwrite
              NODE_INDEX=$(( $NODE_INDEX + 1 ))
          done
     else
          echo "Invalid parameter, only support true or false"
          exit 1  
     fi
}

function unlabel_all_nodes_with_label_alllow_deny_egress(){
     for node in `oc get nodes -lnode-role.kubernetes.io/worker= -oname`
     do
         oc label $node node-role.kubernetes.io/allow-egress- --overwrite
         oc label $node node-role.kubernetes.io/deny-egress- --overwrite
     done
}

function generate_node_selector_anp_with_multi_policy_multi_rules_by_tenant(){
    
    TARGET_NS_PREFIX=$1
    PRIORITY=70  #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=/tmp
    TOTAL_NS_BY_TA=${TOTAL_NS_BY_TA:=5}
    if [[ -z $TARGET_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX $TARGET_NS_PREFIX
            exit 1
    fi

    TARGET_NS=`oc get ns |grep -w $TARGET_NS_PREFIX | awk '{print $1}'`
    if [[ -z $TARGET_NS ]];then
            echo "No TARGET_NS_PREFIX $TARGET_NS_PREFIX was found"
            exit 1
    fi

    TOTAL_NODES=`oc get nodes -lnode-role.kubernetes.io/worker= -oname |wc -l`
    if [[ $TOTAL_NODES -lt 3 ]];then
         echo "To run the test case, you have run it on OCP with more than 3 worker node"
         exit 1
    fi

    LABEL_NUM=$(( $TOTAL_NODES / 2 ))
    >${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
    INIT=0
    TENANT_ID=1
    NODE_INDEX=1
    for ns in $TARGET_NS
    do
         IF_NEW_POLICY=$(( $INIT % $TOTAL_NS_BY_TA ))
         oc label ns $ns customer_tenat=ndtenant${TENANT_ID}      

         if [[ $PRIORITY -lt 0 || $PRIORITY -gt 99 ]];then
              echo "Limited the priority $PRIORITY between 0 to 99"
              break
         fi

         if [[ $INIT -gt $LABEL_NUM ]];then
              #reset INTI to 1
              INIT=1
         fi
        
         if [[ $IF_NEW_POLICY -eq 0 ]];then
         echo customer_tenat=ndtenant${TENANT_ID} node-role.kubernetes.io/allow-egress=n$NODE_INDEX 30003 true >>${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
         echo customer_tenat=ndtenant${TENANT_ID} node-role.kubernetes.io/deny-egress=n$NODE_INDEX 30003 false >>${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
cat>${WORKLOAD_TEMPLATE_PATH}/19_anp_allow-traffic-egress-node-selector-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-egress-node-selector-per-ns-to-labeled-node-p${PRIORITY}
spec:
  priority: ${PRIORITY}
  subject:
    pods:
      namespaceSelector:
        matchLabels:
          customer_tenat: ndtenant${TENANT_ID}
      podSelector:
        matchLabels:
          anplabel: anp-restricted
  egress:
  - name: "allow egress"
    action: "Allow"
    to:
    - nodes:
        matchExpressions:
        - key: node-role.kubernetes.io/allow-egress
          operator: In
          values:
          - "n$NODE_INDEX"
    ports:
    - portNumber:
        port: 10256
        protocol: TCP
    - portNumber:
        protocol: TCP
        port: 53
    - portNumber:
        protocol: UDP
        port: 53
    - portNumber:
        port: 8081
        protocol: TCP 
    - portNumber:
        port: 9100
        protocol: TCP
    - portNumber:
        port: 8798
        protocol: TCP
    - portNumber:
        port: 8443
        protocol: TCP
    - portNumber:
        port: 8444
        protocol: TCP        
    - portRange:
        start: 30001
        end: 30003
        protocol: TCP                                          
  - name: "deny egress"
    action: "Deny"
    to:
    - nodes:
        matchExpressions:
        - key: node-role.kubernetes.io/deny-egress
          operator: In
          values:
          -  "n$NODE_INDEX"
  - name: "pass egress"
    action: "Pass"
    to:
    - nodes:
        matchExpressions:
        - key: node-role.kubernetes.io/worker
          operator: Exists
    ports:          
    - portNumber:
        port: 10250
        protocol: TCP
    - portNumber:
        port: 8444
        protocol: TCP          
EOF
              PRIORITY=$(( $PRIORITY + 1 ))
              TENANT_ID=$(( $TENANT_ID + 1 ))
              NODE_INDEX=$(( $NODE_INDEX + 1 ))
         fi
             INIT=$(( $INIT + 1 ))
    done

    #oc -n openshift-kube-apiserver get pods -owide |grep kube-apiserver | awk '{print $6}'
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/19_anp_allow-traffic-egress-node-selector-*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done
    echo "---------------------------------------------------------------------------------"
    oc get anp | grep allow-traffic-egress-node-selector-per-ns-to-labeled-node-p
    export TOTAL_ANP=`oc get anp | grep allow-traffic-egress-node-selector-per-ns-to-labeled-node-p|wc -l`
    echo "---------------------------------------------------------------------------------"
    echo "The total anp is $TOTAL_ANP"
    echo    
    export TEST_STEP="Creating ${TOTAL_ANP} Node Selector ANP/1 ANP Per Tenant(10 NS)"      
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`  
    get_ovn_node_system_usage_info

    echo "map tenant with node label, we will use this to check result"
    echo "---------------------------------------------------------------------------------"
    cat ${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
    echo "---------------------------------------------------------------------------------"

    MAPFILE=${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
    MAP_NS_FILE=${WORKLOAD_TEMPLATE_PATH}/map-ns-label.lst
    >$MAP_NS_FILE
    TOTALLINE=`cat $MAPFILE |wc -l`
    for (( i=1;i<=$TOTALLINE;i++ ))
    do
       NS_LABEL=`cat $MAPFILE | sed -n "${i}p" | awk '{print $1}'`
       NODE_PORT_MAP=`cat $MAPFILE | sed -n "${i}p" | cut -d" " -f2-`
       for ns in `oc get ns -l${NS_LABEL} -oname | awk -F'/' '{print $2}'`
       do
           echo $ns $NODE_PORT_MAP >>$MAP_NS_FILE
       done
    done

    echo "map namespace with node label, we will use this to check result"
    echo "---------------------------------------------------------------------------------"
    cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-label.lst | sort -k4
    echo "---------------------------------------------------------------------------------"

    TOTALLINE=`cat $MAP_NS_FILE |wc -l`
    for (( i=1;i<=$TOTALLINE;i++ ))
    do
       echo format_Output_ANP_BANP_Source2Host `cat $MAP_NS_FILE | sort -k4 | sed -n "${i}p"`
       format_Output_ANP_BANP_Source2Host `cat $MAP_NS_FILE | sort -k4 | sed -n "${i}p"`
    done
}

function create_node_selector_anp_and_verify_traffic_from_different_ns_groups_to_host(){
    
    WORKLOAD_TEMPLATE_PATH=/tmp
    SOURCE_NS_FILTER="anp-node"
    TARGET_NS_FILTER="anp-test"

    export TEST_STEP="Creating Node Selector ANP to Allow Egress to Worker Nodes Gropus"
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    echo "Creating Node Selector ANP to Allow Egress to Worker Nodes Gropus" 
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

    echo "-----The egress of $SOURCE_NS_FILTER deny to all node network--------"
    #################################Verify Default Policy of BANP##########################################
    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 10250 false
    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 30003 false

    #No limitation to access host network for anp-test by default
    format_Output_ANP_BANP_Source2Host $TARGET_NS_FILTER "node-role.kubernetes.io/worker" 10250 true
    format_Output_ANP_BANP_Source2Host $TARGET_NS_FILTER "node-role.kubernetes.io/worker" 30003 true


    echo "Creating 1 Node Selector ANP to Allow/Deny Egress to access different ports that exposed on worker nodes"
     
    oc apply -f 19-anp_allow-traffic-egress-node-ns-p19.yaml
    printYAMLFile 19-anp_allow-traffic-egress-node-ns-p19.yaml

    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 30003 true
    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 10250 false    


    SOURCE_NS_FILTER="anp-restricted"
    export IF_LABEL_IN_ORDER="true"  
    label_node_with_label_allow_deny_egress
    generate_node_selector_anp_with_multi_policy_multi_rules_by_tenant $SOURCE_NS_FILTER

    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    get_ovn_node_system_usage_info

}

function create_cidr_selector_anp_and_verify_traffic_between_different_ns_groups(){
    
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
    SOURCE_NS_FILTER="anp-cidr"
    TARGET_NS_FILTER="anp-pcidr"
 
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    echo "Creating CIDR Selector ANP Egress/Ingress Policy[Min]"
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

    #The two cidr NS group can not access each other by default
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false

    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false

    echo "#########################################################################"
    echo "#        Dely traffic $SOURCE_NS_FILTER to internet zones               #"
    echo "#########################################################################"   
    echo "-------------------------------------------------------------------------"
    check_traffic_to_internet $SOURCE_NS_FILTER false
    echo "-------------------------------------------------------------------------"
    echo "#########################################################################"
    echo "#        Allow traffic $TARGET_NS_FILTER to internet zones               #"
    echo "#########################################################################"       
    echo "-------------------------------------------------------------------------"
    check_traffic_to_internet $TARGET_NS_FILTER false
    echo "-------------------------------------------------------------------------"
    
    #CIDR Selector ANP to allow ip segment to OCP network
    #But we try to create more ANPs, so limited each POD IP as rules
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    generate_cidr_selector_anp_multipolicy_with_multi_rules_multi_ips_bytenant anp-cidr anp-pcidr

    echo "---------------------------------------------------------------------------------"
    oc get anp | grep allow-traffic-cidr-anp-open-network-tenant
    export TOTAL_ANP=`oc get anp | grep allow-traffic-cidr-anp-open-network-tenant|wc -l`
    echo "---------------------------------------------------------------------------------"
    echo "The total anp is $TOTAL_ANP"
    echo
    echo "Creating $TOTAL_ANP CIDR Selector ANP/1 ANP Per Tenant(10 NS)"
    export TEST_STEP="Creating $TOTAL_ANP Multi ANP with Multi Rule/Multi IP Per Rule"
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    get_ovn_node_system_usage_info

    TOTAL_LINE=`cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst|head -20 |wc -l`
    for ((i=1;i<=$TOTAL_LINE;i++))
    do
        SOURCE_NS_FILTER=`sed -n "${i}p" ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst| awk '{print $1}'`
        TARGET_NS_FILTER=`sed -n "${i}p" ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst| awk '{print $2}'`
        format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
        format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false
    done

    SOURCE_NS_FILTER="anp-cidr"
    TARGET_NS_FILTER="perfscale-workload"
    ########Should Block Connection From Other Tenant###################################
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source  $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false
}

function create_large_scale_network_policy(){
      NS=$1
      IF_APPEND_ONLY=$2
      #export CUSTOMIZED_ITERATIONS=$2            
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
      echo "Creating network policy customized workload for $NS"
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
      
      if [[ $IF_APPEND_ONLY == "true" ]];then
           echo "Append the customized workload to the existing workload"
           CUSTOMIZED_WORKLOAD_FILE=customized-workload.yml
           append_customized_workload_without_inputvar networkpolicy-deny-all.yml
           append_customized_workload_without_inputvar networkpolicy-allowdns.yml
           append_customized_workload_without_inputvar networkpolicy-egress-within-same-ns.yml
           echo -e "        inputVars:\n          selected_pod_type: \"perfapp\"\n          ingress_pod_type: \"perfdb\"\n          ns_label: \"anplabel\"\n          ns_label_value: \"${NS}\"\n          pod_label: \"type\"\n          pod_label_value: perfdb">> $CUSTOMIZED_WORKLOAD_FILE   
           append_customized_workload_without_inputvar networkpolicy-ingress-within-same-ns.yml
           echo -e "        inputVars:\n          selected_pod_type: \"perfdb\"\n          ingress_pod_type: \"perfapp\"\n          anplabel: \"${NS}\"">> $CUSTOMIZED_WORKLOAD_FILE           
      else
           echo "Create the customized workload from scratch"
           CUSTOMIZED_WORKLOAD_FILE=customized-workload.yml
           create_customized_workload $NS networkpolicy
           append_customized_workload_without_inputvar networkpolicy-deny-all.yml
           append_customized_workload_without_inputvar networkpolicy-allowdns.yml
           append_customized_workload_without_inputvar networkpolicy-egress-within-same-ns.yml    
           echo -e "        inputVars:\n          selected_pod_type: \"perfapp\"\n          ingress_pod_type: \"perfdb\"\n          ns_label: \"anplabel\"\n          ns_label_value: \"${NS}\"\n          pod_label: \"type\"\n          pod_label_value: perfdb">> $CUSTOMIZED_WORKLOAD_FILE   
           append_customized_workload_without_inputvar networkpolicy-ingress-within-same-ns.yml
           echo -e "        inputVars:\n          selected_pod_type: \"perfdb\"\n          ingress_pod_type: \"perfapp\"\n          anplabel: \"${NS}\"">> $CUSTOMIZED_WORKLOAD_FILE
    
           cat $CUSTOMIZED_WORKLOAD_FILE
           echo  ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
           ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
           if [[ $? -ne 0 ]];then
                echo "Failed to run the customized workload for $NS"
                exit 1
           fi
      fi

      if [[ $IF_EANBLE_OVNPOD_LOGGING == "true" ]];then
            waiting_for_during_each_phase "Enable OVN POD Logging Phase" 900 "before enable OVN POD logging"
            enable_ovn_node_pod_logging_level
            waiting_for_during_each_phase "Enable OVN POD Logging Phase" 900 "after enable OVN POD logging"
      fi

}

function waiting_for_during_each_phase(){
    PHASE=$1
    SLEEP_TIME=$2
    PROMPT_MESSAGE=$3
    
    if [[ ${IF_SLEEP_WAIT_IN_EACH_PHASE} == "true" ]];then
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'   
             echo "$PHASE: Waiting for $SLEEP_TIME seconds $PROMPT_MESSAGE"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
             sleep $SLEEP_TIME
    fi
}

function enable_anp_audit_logging_level(){
 
  awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
  echo "Enable ANP Audit Logging ...."
  awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
  export TEST_STEP="Enable ANP Logging."
  export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`  
  oc annotate banp default k8s.ovn.org/acl-logging='{ "deny": "alert", "allow": "alert", "pass" : "warning" }'
  for anpName in `oc get anp |grep -v NAME | awk '{print $1}'`
  do
     oc annotate anp $anpName k8s.ovn.org/acl-logging='{ "deny": "alert", "allow": "alert", "pass" : "warning" }'
  done
  export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
  get_ovn_node_system_usage_info 
}

function enable_ovn_node_pod_logging_level(){
 
  awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
  echo "Enable OVN POD Debug Logging ...."
  awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}' 
  export TEST_STEP="Enable OVN POD Debug Logging."
  export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
     WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress                   
cat>${WORKLOAD_TEMPLATE_PATH}/env-overrides.yaml<<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: env-overrides
  namespace: openshift-ovn-kubernetes
data:
  _master: | 
    # This sets the log level for the ovn-kubernetes master process as well as the ovn-dbchecker:
    OVN_KUBE_LOG_LEVEL=5
    # You might also/instead want to enable debug logging for northd, nbdb and sbdb on all masters:
    OVN_LOG_LEVEL=dbg
EOF
   for workerNode in `oc get nodes |grep worker| awk '{print $1}'`
   do
      echo -e "  ${workerNode}: |\n    OVN_KUBE_LOG_LEVEL=5\n    OVN_LOG_LEVEL=dbg"       
   done
   oc apply -n openshift-ovn-kubernetes -f ${WORKLOAD_TEMPLATE_PATH}/env-overrides.yaml
   for ovnNodePods in `oc -n openshift-ovn-kubernetes get pods |grep ovnkube-node| awk '{print $1}'`
   do
       oc -n openshift-ovn-kubernetes delete pod $ovnNodePods
       sleep 10
   done
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
   get_ovn_node_system_usage_info 
}

function restartOVNPODs(){
      echo "Save old node name and ovn pod list to old-node-ovn-pods.lst when ovn pod restart"
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
      oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
      oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst
      cat /tmp/ocp-node-ovn-pods-old.lst
      echo

      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
      echo "Restart OVN Pods"
      OVN_NODE_POD_NAMES=`oc -n openshift-ovn-kubernetes  get pods |grep -v -i -E 'ovnkube-control-plane|NAME' | awk '{print $1}'| tail -5`
      for ovn_node_pod in $OVN_NODE_POD_NAMES
      do  
           echo restart pod $ovn_node_pod
           oc -n openshift-ovn-kubernetes delete pod $ovn_node_pod
      done
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
      export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
      get_ovn_node_system_usage_info
      sleep 30

      oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
      oc get nodes |grep -v -i NAME| awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
      echo "New ovn pods after restart OVN Node Pods"
      awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
      cat /tmp/ocp-node-ovn-pods-*.lst |sort -r| uniq -u
      echo 
      cat /tmp/ocp-node-ovn-pods-*.lst |sort -r| uniq -u| tr -s "\n" "|"
      echo
}

function create_large_scale_anp_networkpolicy_egressfirewall_policy(){
       IF_CIDR_ANP=${IF_CIDR_ANP:="false"}
       IF_NODE_ANP=${IF_NODE_ANP:="false"}
       IF_MASTER_CARD_CASE=${IF_MASTER_CARD_CASE:="false"}
       IF_RECYCLE_NODE=${IF_RECYCLE_NODE:="true"}
       WORKLOAD_TEMPLATE_PATH=workloads/mixed-scenario/customized-workloads
 
       ###################################Create Default BANP#################################
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
       echo "Creating default BANP default to deny traffic for restricted workload as zero trust policy"
      
       export TEST_STEP="Creating default BANP"
       export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`

       oc apply -f 00_banp-default-deny-traffic.yml 
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'      
       oc apply -f 00_banp-default-deny-traffic.yml
       printYAMLFile 00_banp-default-deny-traffic.yml          
       export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
       get_ovn_node_system_usage_info
 
       create_pod_selector_anp_and_verify_traffic_between_ns_groups

       ###################################Create CIDR Selector Policy#################################   
       create_cidr_selector_anp_and_verify_traffic_between_different_ns_groups

       ###################################Create Node Selector Policy#################################
       unlabel_all_nodes_with_label_alllow_deny_egress
       create_node_selector_anp_and_verify_traffic_from_different_ns_groups_to_host

       #Enable common service for restricted workload will affect the traffic between different zones
       echo "Creating ANP to allow common service for restricted workload"
       export TEST_STEP="Creating ANP - allow common service policy"
       oc apply -f 01_anp-allow-common-service.yml
       printYAMLFile 01_anp-allow-common-service.yml       

       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
       echo "Creating total `oc get anp| wc -l` ANPs"
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
       oc get anp
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

       if [[ $IF_EANBLE_ANP_LOGGING == "true" ]];then
            waiting_for_during_each_phase "Enable ANP Logging Phase" 900 "before enable ANP logging"
            enable_anp_audit_logging_level
            waiting_for_during_each_phase "Enable ANP Logging Phase" 900 "after enable ANP logging"
       fi

}