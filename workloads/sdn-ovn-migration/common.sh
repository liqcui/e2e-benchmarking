#!/usr/bin/bash
source ../../utils/common.sh

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
  EGRESS_FIREWALL_POLICY_IP_SEGMENT_ALLOW=${EGRESS_FIREWALL_POLICY_IP_SEGMENT_ALLOW:="5.110.1"}
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
  #  unset TEST_STEP CREATE_TIME QUERY_TIME MAX_MASTER_CPU MAX_MASTER_RAM MAX_WORKER_CPU MAX_WORKER_RAM ACL MATCH_ACL PORT_GROUP_UUID ADDRESS_SET_UUID EGRESS_RULES_NUMS_BY_NS LFLOW DUMP_FLOW_BR_INT
  #unset TEST_STEP CREATE_TIME QUERY_TIME MAX_MASTER_CPU MAX_MASTER_RAM MAX_WORKER_CPU MAX_WORKER_RAM ACL MATCH_ACL PORT_GROUP_UUID ADDRESS_SET_UUID EGRESS_RULES_NUMS_BY_NS LFLOW DUMP_FLOW_BR_INT
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
function scaleupDeployment(){
export SCALE_POD_REPLICAS=${SCALE_POD_REPLICAS:="100"}  
oc apply -f-<<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scale-up
  labels:
    app: scale-up
spec:
  replicas: ${SCALE_POD_REPLICAS}
  selector:
    matchLabels:
      app: scale-up
  template:
    metadata:
      labels:
        app: scale-up
    spec:
      nodeSelector: 
        node-role.kubernetes.io/worker: ""
      containers:
      - name: busybox
        image: quay.io/openshifttest/busybox@sha256:c5439d7db88ab5423999530349d327b04279ad3161d7596d2126dfb5b02bfd1f
        resources:
          requests:
            memory: 4Gi
        command:
        - /bin/sh
        - "-c"
        - "echo 'this should be in the logs' && sleep 86400"
      terminationGracePeriodSeconds: 0
EOF
}

#####################################

function enable_kube_burner_index(){
    export START_TIME=${START_TIME:=""}
    export END_TIME=${END_TIME:-""}
    export ES_INDEX=${ES_INDEX:=ovn-live-migration}
    export LOG_LEVEL=debug
    METRICS_PROFILE=metrics-profiles/metrics.yml
   
    START_TIME=`date --date="30 min ago" +"%s"`
    END_TIME=`date +"%s"`
    echo ${KUBE_DIR}/kube-burner-ocp index --uuid=${UUID} --start=$START_TIME --end=$((END_TIME + 600)) --metrics-profile=$METRICS_PROFILE  --es-server=${ES_SERVER} --es-index=${ES_INDEX}
    ${KUBE_DIR}/kube-burner-ocp index --uuid=${UUID} --start=$START_TIME --end=$((END_TIME + 600)) --metrics-profile=$METRICS_PROFILE  --es-server=${ES_SERVER} --es-index=${ES_INDEX}
    JOB_START=$(date -u -d "@$START_TIME" +"%Y-%m-%dT%H:%M:%SZ")
    JOB_END=$(date -u -d "@$((END_TIME + 600))" +"%Y-%m-%dT%H:%M:%SZ")
}

function capture_sdn_log4minSyncPeriod(){

nodeList=`oc get nodes |grep  Ready| awk '{print $1}' |grep -v NAME|tail -5`
for node in $nodeList
do
	echo ---------------------------------- | tee -a /tmp/minSyncPeriod.log
	podname=`oc -n openshift-sdn get pods -lapp=sdn -owide |grep $node| awk '{print $1}'`
	echo $node:$podname | tee -a /tmp/minSyncPeriod.log
	oc -n openshift-sdn logs $podname -c sdn |grep minSyncPeriod | tee -a /tmp/minSyncPeriod.log
done

nodeList=`oc get nodes |grep -v -w Ready| awk '{print $1}'|grep -v NAME`
for node in $nodeList
do
	echo ---------------------------------- | tee -a /tmp/minSyncPeriod.log
	podname=`oc -n openshift-sdn get pods -lapp=sdn -owide |grep $node| awk '{print $1}'`
	echo $node:$podname | tee -a /tmp/minSyncPeriod.log
	oc -n openshift-sdn logs $podname -c sdn |grep minSyncPeriod | tee -a /tmp/minSyncPeriod.log
done

}

function sdn-ovn-live-migration-keepalive-detect-phaseI(){
    LIVE_MIGRATION_DETECT_INTERVAL=${LIVE_MIGRATION_DETECT_INTERVAL:=3}
    INIT=1
    MAX_RETRY=${MAX_RETRY:=7200}
    echo The max retry is $MAX_RETRY
    export BEFORE_N_TYPE=$(oc get Network.operator.openshift.io cluster  -o json | jq -r '.spec.defaultNetwork.type')
    oc get mcp |grep infra>/dev/null
    RC1=$?
    oc get mcp |grep workload>/dev/null
    RC2=$?
    NETWORK_TYPE=`oc get network.config.openshift.io cluster -o jsonpath='{.status.networkType}'`
    if [[ $RC1 -ne 0 || $RC2 -ne 0 || $NETWORK_TYPE == "OVNKubernetes" ]];then
        echo please enable infra and workload node or the cluster is already OVNKubernetes network
        exit 1
    fi

    if ! oc get route -A |grep keepalive-detect-nginx-cluster-ip-service; then
        echo "Create a route service to public network"
        oc -n sdn-ovn-migration-0 create route edge --service=keepalive-detect-nginx-cluster-ip-service
    fi
    echo "Start to OVN live migration ...."
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    #oc patch Network.config.openshift.io cluster --type='merge' --patch '{"metadata":{"annotations":{"unsupported-red-hat-internal-testing": "true"}}}'
    oc patch Network.config.openshift.io cluster --type='merge' --patch '{"metadata":{"annotations":{"network.openshift.io/network-type-migration":""}},"spec":{"networkType":"OVNKubernetes"}}'
    #4.15 oc patch Network.operator.openshift.io cluster --type='merge' --patch '{ "spec": { "migration": {"networkType": "OVNKubernetes" } } }'
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    export NW_MIGRATION_START=$(date +%s)
    echo "Start to delect if businees/service down in phase I of OVN live migration ...."
    DETECT_ROUTE_NAME=`oc get route -A|grep keepalive-detect | awk '{print $3}'`
    isPrompted=false
    while true;
    do
                curl -k -Is https://${DETECT_ROUTE_NAME}/ | head -n 3| grep OK;
                RC=$?;

                if [[ $EnableAutoScaler == "true" ]];then
                     oc get pvc -n openshift-monitoring
                     oc get pv
                     oc -n openshift-machine-api get machineset
                else
                     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                     oc get mcp | awk '{print $1" "$3"\t"$4"\t"$5"\t "$6"\t"$7"\t"$7"\t"$9}' 
                     oc -n openshift-apiserver get pods | grep apiserver >/dev/null
                fi        
                RC1=$?
                if [ $RC1 -ne 0 ] ; then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       [Failure] oc cli broken during ovn live migration at `date +"%Y-%m-%d %H:%M:%S"`      #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'        
                   echo
                fi

                if [ $RC -ne 0 ] ; then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       [Failure] Service broken during ovn live migration at `date +"%Y-%m-%d %H:%M:%S"`      #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'        
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo "curl -k -Is https://${DETECT_ROUTE_NAME}/ output ....."
                   curl -k -Is https://${DETECT_ROUTE_NAME}/
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo "curl -k -v https://${DETECT_ROUTE_NAME}/ output ....."                   
                   curl -k -v https://${DETECT_ROUTE_NAME}/
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo 
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo "oc get network.config -o yaml output ....."                   
                   oc get network.config -o yaml
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'                   
                  #  echo
                  #  awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                  #  oc adm must-gather  -- gather_network_logs>/tmp/must-gather.log
                  #  awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   oc get pods -A |grep -i -v -E 'Running|cluster-density|Completed'
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
                   oc get nodes |grep -w -v Ready
                   awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
                fi;
                NETWORK_TYPE=`oc get network.config.openshift.io cluster -o jsonpath='{.status.networkType}'`
    
                if [[ $NETWORK_TYPE == "OVNKubernetes" ]];then
                #if [[ $NETWORK_TYPE == "OpenShiftSDN" ]];then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       The OCP Network Type Changed to $NETWORK_TYPE at `date +"%Y-%m-%d %H:%M:%S"`         #"
                   echo "#                     Current Network Type is $NETWORK_TYPE                    #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'     
                   break
                fi
                if [[ $EnableAutoScaler == "true" && INIT -eq 900 ]];then
                    echo "#########################################################"
                    echo "#Creating scale-up pod to trigger scale out workload node#"
                    echo "#########################################################"
                    scaleupDeployment
                fi
                if [[ $EnableAutoScaler == "true" && INIT -eq 2100 ]];then
                    echo "##########################################################"
                    echo "#Deleting scale-up pod to trigger scale down workload node#"
                    echo "##########################################################"
                    oc delete deployment scale-up
                fi

                

                if [[ $(( $INIT%240 )) -eq 0 ]];then
                  export TEST_STEP="OVN live migration - sdn network - $INIT"
                  export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
                  export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
                  get_ovn_node_system_usage_info
                fi
                oc get mcp | awk '{print $4}'|grep -w True >/dev/null
                RC3=$?
                if [[ $RC3 -eq 0 && $isPrompted=="false" ]] ; then
                    isPrompted=true
                    echo "mcp is updating and rebooting"
                fi
                #Temp solution for pr649 and will remove later
                # if [ $RC3 -eq 0 -a $(( $INIT%60 )) -eq 0 ];then
                #    capture_sdn_log4minSyncPeriod
                # fi

                sleep $LIVE_MIGRATION_DETECT_INTERVAL;
                INIT=$(( $INIT + 1 ))
                if [[ $INIT -gt $MAX_RETRY ]];then
                   echo "max retry reached in live-migration-post-check"
                   exit 1
                fi
    done

    #Temp solution for pr649 and will remove later
    # if [[ -f /tmp/minSyncPeriod.log ]];then
    #    cat /tmp/minSyncPeriod.log
    # fi
}

function sdn-ovn-live-migration-keepalive-detect-phaseII(){
    INIT=1
    MAX_RETRY=${MAX_RETRY:=7200}
    LIVE_MIGRATION_DETECT_INTERVAL=${LIVE_MIGRATION_DETECT_INTERVAL:=3}
    echo The max retry is $MAX_RETRY
    echo "Start to detect if the service broken during the second reboot of OVN live migration ...."
    
    DETECT_ROUTE_NAME=`oc get route -A|grep keepalive-detect | awk '{print $3}'`
    while true;
    do
                if [[ $EnableAutoScaler == "true" ]];then
                     awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                     oc get pvc -n openshift-monitoring
                     oc get pv
                     awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                     oc get mcp
                     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                     oc get node |grep infra
                     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'                     
                     oc -n openshift-machine-api get machineset
                     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                else
                     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                     oc get mcp | awk '{print $1" "$3"\t"$4"\t"$5"\t "$6"\t"$7"\t"$7"\t"$9}'               
                     oc -n openshift-apiserver get pods | grep apiserver >/dev/null
                fi            
               
                RC1=$?
                if [ $RC1 -ne 0 ] ; then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       [Failure] oc cli broken during ovn live migration at `date +"%Y-%m-%d %H:%M:%S"`      #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'        
                   echo
                fi

                curl -k -Is https://${DETECT_ROUTE_NAME}/ | head -n 3 | grep OK;
                RC=$?;
                if [ $RC -ne 0 ] ; then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       [Failure] Service broken during ovn live migration at `date +"%Y-%m-%d %H:%M:%S"`      #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   oc get mcp
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo "curl -k -Is https://${DETECT_ROUTE_NAME}/ output ....."
                   curl -k -Is https://${DETECT_ROUTE_NAME}/
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo "curl curl -k -v https://${DETECT_ROUTE_NAME}/ output ....."                   
                   curl -k -v https://${DETECT_ROUTE_NAME}/
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo 
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo "oc get network.config -o yaml output ....."                   
                   oc get network.config -o yaml
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'                   
                  #  echo
                  #  awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                  #  oc adm must-gather  -- gather_network_logs>/tmp/must-gather.log
                  #  awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   oc get pods -A |grep -i -v -E 'Running|cluster-density|Completed'
                   awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                   echo
                   awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
                   oc get nodes |grep -w -v Ready
                   awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
                fi;
               
                MASTER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name master`
                WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name worker`
                INFRA_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name infra`
                WORKLOAD_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name workload`
                # echo $MASTER_MCP_STATUS $WORKER_MCP_STATUS $INFRA_MCP_STATUS $WORKLOAD_MCP_STATUS
                #if [[ $MASTER_MCP_STATUS == "true" && $WORKER_MCP_STATUS == "true" && $INFRA_MCP_STATUS == "true" && $WORKLOAD_MCP_STATUS == "true" && $NETWORK_TYPE == "OpenShiftSDN" ]];then
                oc get network cluster -oyaml |grep NetworkTypeMigrationCompleted>/dev/null
                RC2=$?
                if [[ $MASTER_MCP_STATUS == "true" && $WORKER_MCP_STATUS == "true" && $INFRA_MCP_STATUS == "true" && $WORKLOAD_MCP_STATUS == "true" && $RC2 -eq 0 ]];then
                #if [[ $MASTER_MCP_STATUS == "true" && $WORKER_MCP_STATUS == "true" && $INFRA_MCP_STATUS == "true" && $WORKLOAD_MCP_STATUS == "true" && $NETWORK_TYPE == "OVNKubernetes" ]];then
                #if [[ $NETWORK_TYPE == "OpenShiftSDN" ]];then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#            OVN Live Migration Successfully at `date +"%Y-%m-%d %H:%M:%S"`            #"
                   echo "#                     Current Network Type is $NETWORK_TYPE                    #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'     
                   break
                fi
                sleep $LIVE_MIGRATION_DETECT_INTERVAL;
                if [[ $EnableAutoScaler == "true" && INIT -eq 300 ]];then
                    echo "#########################################################"
                    echo "#Creating scale-up pod to trigger scale out workload node#"
                    echo "#########################################################"
                    scaleupDeployment
                fi
                if [[ $EnableAutoScaler == "true" && INIT -eq 900 ]];then
                    echo "##########################################################"
                    echo "#Deleting scale-up pod to trigger scale down workload node#"
                    echo "##########################################################"
                    oc delete deployment scale-up
                fi

                if [[ $(( $INIT%240 )) -eq 0 ]];then
                  export TEST_STEP="OVN live migration - ovn network - $INIT"
                  export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
                  export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
                  get_ovn_node_system_usage_info
                fi

                INIT=$(( $INIT + 1 ))
                if [[ $INIT -gt $MAX_RETRY ]];then
                   echo "max retry reached in live-migration-post-check"
                   exit 1
                fi
    done

}

function cluster_health_basic_check() {
 
  #target_version_prefix=$1
  echo -e "**************Post Action after upgrade succ****************\n"
  echo -----------------------------------------------------------------------
  echo -e "Post action: #oc get node:\n"
  oc get node -o wide
  echo -----------------------------------------------------------------------
  echo
  echo -e "Post action: #oc get co:\n"
  echo -----------------------------------------------------------------------
  oc get co
  echo -----------------------------------------------------------------------

  echo -e "print detail msg for node(SchedulingDisabled) if exist:\n"
  echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Abnormal node details~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
  nodeStatusCheckResult=${nodeStatusCheckResult:=""}
  if oc get node --no-headers | grep -E 'SchedulingDisabled|NotReady' ; then
                  oc get node --no-headers | grep -E 'SchedulingDisabled|NotReady'| awk '{print $1}'|while read line; do oc describe node $line;done
                  nodeStatusCheckResult="abnormal"
  fi
  echo
  echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
  echo -e "print detail msg for co(AVAILABLE != True or PROGRESSING!=False or DEGRADED!=False or version != target_version) if exist:\n"

  echo nodeStatusCheckResult is $nodeStatusCheckResult
  echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Abnormal co details~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"

  abnormalCO=${abnormalCO:=""}
  echo abnormalCO is $abnormalCO
  ! oc get co -o jsonpath='{range .items[*]}{.metadata.name} {range .status.conditions[*]} {.type}={.status}{end}{"\n"}{end}' | grep -v "openshift-samples" | grep -w -E 'Available=False|Progressing=True|Degraded=True' || abnormalCO=`oc get co -o jsonpath='{range .items[*]}{.metadata.name} {range .status.conditions[*]} {.type}={.status}{end}{"\n"}{end}' | grep -v "openshift-samples" | grep -w -E 'Available=False|Progressing=True|Degraded=True' | awk '{print $1}'`
  echo "abnormalCO is $abnormalCO before quick_diagnosis"

  if [[ "X${abnormalCO}" != "X" ]]; then
      echo "Start quick_diagnosis"
      quick_diagnosis "$abnormalCO"
      for aco in $abnormalCO; do
          oc describe co $aco
          echo -e "\n~~~~~~~~~~~~~~~~~~~~~~~\n"
      done
  fi
  echo abnormalCO is $abnormalCO after quick_diagnosis
  coStatusCheckResult=${coStatusCheckResult:=""}
 ! oc get co |sed '1d'|grep -v "openshift-samples"|grep -v "True        False         False" || coStatusCheckResult=`oc get co |sed '1d'|grep -v "openshift-samples"|grep -v "True        False         False"|awk '{print $1}'|while read line; do oc describe co $line;done`
  echo coStatusCheckResult is $coStatusCheckResult 
  echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"

  coVersionCheckResult=${coVersionCheckResult:=""}
  ! oc get co |sed '1d'|grep -v -E "openshift-samples|aro"|grep -v ${target_version_prefix} || coVersionCheckResult=`oc get co |sed '1d'|grep -v -E "openshift-samples|aro"|grep -v ${target_version_prefix}|awk '{print $1}'|while read line; do oc describe co $line;done`
  echo coVersionCheckResult is $coVersionCheckResult
  echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"


  if [ -z "$nodeStatusCheckResult" ] && [ -z "$coStatusCheckResult" ] && [ -z "$coVersionCheckResult" ]; then
      echo -e "post check passed without err.\n"
  else
      oc get nodes
      oc describe nodes
  fi

}

function sdn_ovn_live_migration_checkpoint(){
     echo "Network connection testing from pod to pod(same node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo "Checking Items, Result, Command,Output">/tmp/checkResult.csv
     POD_NAME=`oc -n sdn-ovn-migration-0 get pods -ltrafficapp=perfapp -oname |head -1`
     CMD="oc -n sdn-ovn-migration-0 logs $POD_NAME --tail=6 |grep 'Timestamp inserted in'"
     OUTPUT=`oc -n sdn-ovn-migration-0 logs $POD_NAME --tail=6 |grep 'Timestamp inserted in' |tail -1`
     oc -n sdn-ovn-migration-0 logs $POD_NAME --tail=6 |grep 'Timestamp inserted in'
     if [[ $? -eq 0 ]];then
        echo "Network connection testing from pod to pod(same node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to pod(same node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to pod(cross node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pod -lapp=external-traffic -oname`
     POD_IP=`oc -n sdn-ovn-migration-0 get pod -lapp=workload-nginx-app -ojsonpath={.items[0].status.podIP}`
     CMD="oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $POD_IP 8080"
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $POD_IP 8080 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`

     oc -n sdn-ovn-migration-0 exec -i $SOURCE_POD_NAME -- nc -vz $POD_IP 8080
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to pod(cross node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to pod(cross node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to host(same node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pod -lapp=external-traffic -oname`
     HOST_IP=`oc -n sdn-ovn-migration-0 get $SOURCE_POD_NAME -ojsonpath={.status.hostIP}`
     CMD="oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250"
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`
     oc -n sdn-ovn-migration-0 exec -i $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to host(same node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to host(same node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to host(cross node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pod -lapp=external-traffic -oname`
     HOST_IP=`oc -n sdn-ovn-migration-0 get pod -lapp=workload-nginx-app -ojsonpath={.items[0].status.hostIP}`
     CMD="oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250"
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`
     oc -n sdn-ovn-migration-0 exec -i $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to host(cross node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to host(cross node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to ClusterIP service"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n get pod -lapp=external-traffic -oname`
     CMD="oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz keepalive-detect-nginx-cluster-ip-service 8080"
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz keepalive-detect-nginx-cluster-ip-service 8080 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`
     oc -n sdn-ovn-migration-0 exec -i $SOURCE_POD_NAME -- nc -vz keepalive-detect-nginx-cluster-ip-service 8080
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to ClusterIP service,Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to ClusterIP service,Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to NodePort service(same node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     NODE_LABEL=node-role.kubernetes.io/workload
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pods -lapp=workload-tool -oname`
     HOST_IP=`oc get nodes -l"${NODE_LABEL}" -ojsonpath='{range .items[0]}{.status.addresses[?(@.type=="InternalIP")].address}'`
     CMD="oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036"
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to NodePort service(same node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from pod to NodePort service(same node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to NodePort service(cross node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     NODE_LABEL=node-role.kubernetes.io/workload
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pod -lapp=external-traffic -oname`
     HOST_IP=`oc get nodes -l"${NODE_LABEL}" -ojsonpath='{range .items[0]}{.status.addresses[?(@.type=="InternalIP")].address}'`
     CMD="oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036"
     oc -n sdn-ovn-migration-0 exec $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`
     oc -n sdn-ovn-migration-0 exec -i $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to NodePort service(cross node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from pod to NodePort service(cross node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from external to NodePort service"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     MASTER_NODE=`oc get node |grep -E 'control-plane|master' | awk '{print $1}'| head -1`
     NODE_LABEL=node-role.kubernetes.io/workload
     HOST_IP=`oc get nodes -l"${NODE_LABEL}" -ojsonpath='{range .items[0]}{.status.addresses[?(@.type=="InternalIP")].address}'`
     CMD="oc -n sdn-ovn-migration-0 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 30036"
     oc -n sdn-ovn-migration-0 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 30036 >/tmp/oc-output 2>&1
     OUTPUT=`grep Connected /tmp/oc-output`
     oc -n sdn-ovn-migration-0 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 30036
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from external to NodePort service(cross node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from external to NodePort service,Failure(cross node),$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to external"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     NODE_LABEL=node-role.kubernetes.io/workload
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pod -lapp=external-traffic -oname`
     CMD="oc -n sdn-ovn-migration-0 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'"
     oc -n sdn-ovn-migration-0 logs $SOURCE_POD_NAME --tail=20 >/tmp/oc-output 2>&1
     OUTPUT=`cat /tmp/oc-output |grep 'HTTP/.* 200'| head -1`
     oc -n sdn-ovn-migration-0 exec -i $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to external,Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from pod to external,Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from externl to loadbalancer service"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     #ibmcloude
     #oc -n sdn-ovn-migration-0 get services keepalive-detect-nginx-loadbalancer-service -ojsonpath='{.status.loadBalancer.ingress[0].hostname}'
     HOST_IP=`oc -n sdn-ovn-migration-0 get services | grep keepalive-detect-nginx-loadbalancer-service | awk '{print $4}'`
     SOURCE_POD_NAME=`oc -n sdn-ovn-migration-0 get pod -lapp=external-traffic -oname`
     CMD="oc -n sdn-ovn-migration-0 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 8080 | grep Connected"
     oc -n sdn-ovn-migration-0 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 8080 >/tmp/oc-output 2>&1
     OUTPUT=`cat /tmp/oc-output |grep Connected`
     oc -n sdn-ovn-migration-0 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 8080 |grep Connected
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from externl to loadbalancer service,Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from externl to loadbalancer service,Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo
     echo "######################Network Policy####################################"
     echo "Network connection testing from pod to pod with netpol(cross ns)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n sdn-ovn-restricted-0  get pods -ltrafficapp=perfata -oname | head -1`
     CMD="oc -n sdn-ovn-restricted-0 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'"
     oc -n sdn-ovn-restricted-0 logs $SOURCE_POD_NAME --tail=20 >/tmp/oc-output 2>&1
     OUTPUT=`cat /tmp/oc-output |grep 'HTTP/.* 200' | head -1`
     oc -n sdn-ovn-restricted-0 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod with netpol(cross ns),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from pod with netpol(cross ns),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo
     echo "Network connection testing from pod to pod with netpol(same ns)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n sdn-ovn-restricted-0  get pods -ltrafficapp=perfapp -oname | head -1`
     CMD="oc -n sdn-ovn-restricted-0 logs $SOURCE_POD_NAME --tail=20|grep 'Timestamp inserted'"
     oc -n sdn-ovn-restricted-0 logs $SOURCE_POD_NAME --tail=20 >/tmp/oc-output 2>&1
     OUTPUT=`cat /tmp/oc-output |grep 'Timestamp inserted' | head -1`
     oc -n sdn-ovn-restricted-0 logs $SOURCE_POD_NAME --tail=20|grep 'Timestamp inserted'
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod with netpol(same ns),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from pod with netpol(same ns),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo
     echo "###############################Summary Report##################################"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     cat /tmp/checkResult.csv
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc get csr
     oc get csr    
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc get co
     oc get co 
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc get nodes
     oc get nodes
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc get mcp
     oc get mcp
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc get mc
     oc get mc
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc -n openshift-ovn-kubernetes get pods
     oc -n openshift-ovn-kubernetes get pods
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo oc get network cluster -ojsonpath='{.status.networkType}'
     oc get network cluster -ojsonpath='{.status.networkType}'    
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'   
     echo oc get pods -A |grep -v -E 'Running|Complete'
     oc get pods -A |grep -v -E 'Running|Complete'
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
     echo  oc -n openshift-ingress  get pods 
     oc -n openshift-ingress  get pods 
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
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
         for workerNode in `oc get nodes |grep worker | awk '{print $1}'|head -30`
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
         export TEST_STEP="After reboot nodes when OVN CNI migration complete"
         export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
         export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
         get_ovn_node_system_usage_info
    fi
}

create_ingress_controller(){
  
DEFAULT_INGRESS_CONTROLLER=`oc get nodes -lnode-role.kubernetes.io/worker |wc -l | tr -d ' '`
MAX_INGRESS_CONTROLLER=${MAX_INGRESS_CONTROLLER:=$DEFAULT_INGRESS_CONTROLLER}
echo "Creating $MAX_INGRESS_CONTROLLER ingress controller, the replicas is 2"
OCP_COMMON_DOMAIN_NAME=`oc -n openshift-ingress-operator get ingresscontroller default -ojsonpath={.status.domain}`
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650   -nodes -keyout tls.key -out tls.crt -subj "/CN=perfsale-qe.com"   -addext "subjectAltName=DNS:*.${OCP_COMMON_DOMAIN_NAME}"
oc --namespace openshift-ingress create secret tls customized-tls --cert=tls.crt --key=tls.key
INDEX=1

for routename in `oc get route -A | grep cluster-density-v2 | awk '{print $3}' | tail -${MAX_INGRESS_CONTROLLER}`
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

function format_output_align_columns(){
        IF_APPEND=$1
        COL1=$2
        COL2=$3
        COL3=$4
        COL4=$5
        
        if [[ $IF_APPEND == "false" ]];then
            printf "%-60s %-20s %-20s %-20s\n" "$2" "$3" "$4" "$5"
            awk 'BEGIN{for(c=0;c<120;c++) printf "-"; printf "\n"}'
        else
            printf "%-60s %-20s %-20s %-20s\n" "$2" "$3" "$4" "$5"
        fi
}

function post_check_after_migration(){
    JOB_START=$1
    JOB_END=$2
    python3 -m pip install elasticsearch requests urllib3
    export ITERATIONS=${ITERATIONS:=4500}
    INIT=1
    MAX_RETRY=${MAX_RETRY:=720}
    DETECT_INTERVAL=${DETECT_INTERVAL:=30}
    
    echo The max retry is $MAX_RETRY
    echo "Object numbers of ETCD"
    export ETCD_POD_NAME=$(oc get pods -n openshift-etcd -l app=etcd --field-selector="status.phase==Running" -o jsonpath="{.items[0].metadata.name}")
    oc exec -n openshift-etcd ${ETCD_POD_NAME} -- bash -c "etcdctl get / --prefix --keys-only | sed '/^$/d' | cut -d/ -f3 | sort | uniq -c | sort -rn"
    # echo "Object Size of ETCD"
    # oc exec -n openshift-etcd -c etcdctl ${ETCD_POD_NAME} -- sh -c "etcdctl get / --prefix --keys-only  | grep -oE '^/[a-z|.]+/[a-z|.|8]*' | sort | uniq -c | sort -rn" | while read KEY; do printf "$KEY\t" && oc exec -n openshift-etcd ${ETCD_POD_NAME} -c etcdctl -- etcdctl get ${KEY##* } --prefix --write-out=json | jq '[.kvs[].value | length] | add ' | numfmt --to=iec ; done | sort -k3 -hr | column -t

    # oc exec -n openshift-etcd -c etcdctl ${ETCD_POD_NAME} -- sh -c "etcdctl get / --prefix --keys-only  | grep -oE '^/[a-z|.]+/[a-z|.|8]*' | sort | uniq -c | sort -rn| grep -E 'configmap|secrets|events|pods|deployments|serviceaccounts|rolebindings|services|routes|networkpolicies|endpointslices'"|while read KEY; do printf "$KEY\t" && oc exec -n openshift-etcd ${ETCD_POD_NAME} -c etcdctl -- etcdctl get ${KEY##* } --prefix --write-out=json | jq '[.kvs[].value | length] | add ' | numfmt --to=iec ; done

    echo -e "Test Scenario - Limited SDN to OVN Migration:">>/tmp/final-summary.csv
    awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'>>/tmp/final-summary.csv
    format_output_align_columns false "Testing Items" "Value">>/tmp/final-summary.csv
    totalMasterNodes=`oc get nodes |grep -E 'master' |wc -l`
    format_output_align_columns true "MasterNodes," $totalMasterNodes>>/tmp/final-summary.csv
    totalInfraNodes=`oc get nodes |grep -E 'infra' |wc -l`
    format_output_align_columns true "InfraNodes," $totalInfraNodes>>/tmp/final-summary.csv
    totalWorkNodes=`oc get nodes |grep -E 'worker' |wc -l`
    format_output_align_columns true "WorkNodes," $totalWorkNodes>>/tmp/final-summary.csv
    totalNS=`oc get ns| grep cluster-density-v2 |wc -l`
    format_output_align_columns true "totalNS," $totalNS>>/tmp/final-summary.csv
    totalANPs=`oc get anp |grep -v NAME|wc -l` 
    format_output_align_columns true "ANPs," $totalANPs>>/tmp/final-summary.cs
    anpNS1=`oc get ns |grep cluster-density-v2| awk '{print $1}'| head -1`
    networkPolicyPerNS=`oc -n $anpNS1 get networkpolicy |wc -l`
    totalNetworkPolicy=$(( $totalNS * $networkPolicyPerNS ))
    format_output_align_columns true "NetworkPolicy," $totalNetworkPolicy>>/tmp/final-summary.csv
    python3 get_prom_metrics.py -q 'ovnkube_controller_num_egress_firewall_rules' -s $JOB_START -e $JOB_END -t getInfo| head -15 | tee metric_result.txt
    maxValue=`cat metric_result.txt |grep -w No.1| awk '{print  $NF}'| tr -d ' '`  
    format_output_align_columns true "EgressFirewallRules," $maxValue>>/tmp/final-summary.cs
    python3 get_prom_metrics.py -q 'sum(kube_pod_status_phase{}) by (phase)' -s $JOB_START -e $JOB_END -t getInfo| tee metric_result.txt
    maxValue=`cat metric_result.txt |grep -w No.1| awk '{print  $NF}'| tr -d ' '` 
    python3 get_prom_metrics.py -q 'count(kube_secret_info{})' -s $JOB_START -e $JOB_END -t getInfo| tee metric_result.txt
    maxValue=`cat metric_result.txt |grep -w No.1| awk '{print  $NF}'| tr -d ' '`
    format_output_align_columns true "Secret," $maxValue>>/tmp/final-summary.cs
    python3 get_prom_metrics.py -q 'count(kube_configmap_info{})' -s $JOB_START -e $JOB_END -t getInfo| tee metric_result.txt
    maxValue=`cat metric_result.txt |grep -w No.1| awk '{print  $NF}'| tr -d ' '`
    format_output_align_columns true "ConfigMap," $maxValue>>/tmp/final-summary.csv
    
    python3 get_prom_metrics.py -q 'count(kube_service_info{})' -s $JOB_START -e $JOB_END -t getInfo| tee metric_result.txt
    maxValue=`cat metric_result.txt |grep -w No.1| awk '{print  $NF}'| tr -d ' '`
    format_output_align_columns true "Service," $maxValue>>/tmp/final-summary.cs
    python3 get_prom_metrics.py -q 'count(openshift_route_info{})' -s $JOB_START -e $JOB_END -t getInfo| tee metric_result.txt
    maxValue=`cat metric_result.txt |grep -w No.1| awk '{print  $NF}'| tr -d ' '`
    format_output_align_columns true "Route," $maxValue>>/tmp/final-summary.csv
    
    cat /tmp/final-summary.csv
    while true;
    do
          START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
          echo -e "\n\n"
          awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}' 
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'           
          echo "Check OVN Pods Status"
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
          oc -n openshift-ovn-kubernetes get pods | grep -v '8/8'
          
          echo "Get latest 20 event"
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'   
          oc get event -A | sort -n -k1 -r| tail -20

          echo "Get API Logs"
          for apipod in `oc -n openshift-kube-apiserver get pods -l app=openshift-kube-apiserver |grep -v NAME | awk '{print $1}'`
          do
              echo
              echo $apipod
              awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
              oc -n openshift-kube-apiserver logs $apipod --since=90s
          done

          echo "Get kube-controller Logs"
          for kubectrpod in `oc -n openshift-kube-controller-manager get pods -lapp=kube-controller-manager| grep -v NAME| awk '{print $1}'`
          do
              echo
              echo $kubectrpod
              awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
              oc -n openshift-kube-controller-manager logs $kubectrpod -c kube-controller-manager --since=60s
          done

          machineControllerPod=`oc -n openshift-machine-config-operator get pods |grep machine-config-controller| awk '{print $1}'`
          echo "Get machine-config-controller Logs"
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
          oc -n openshift-machine-config-operator logs $machineControllerPod -c machine-config-controller --since=90s
          echo 
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
          echo oc -n openshift-kube-controller-manager get event
          oc -n openshift-kube-controller-manager get event | tail -20

          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
          oc get mcp | awk '{print $1" "$3"\t"$4"\t"$5"\t "$6"\t"$7"\t"$7"\t"$9}'

          echo "----------------------TOP 10 Usage of Containers of OVN Pods---------------------------"
          oc -n openshift-ovn-kubernetes adm top pods --containers| sort -n -r -k4 | head -10

          echo "----------------------TOP 10 Usage of Containers of API Pods---------------------------"
          oc adm -n openshift-kube-apiserver top pod| grep -v guard
       
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
          echo
          oc get node | grep -v -w Ready
          echo

          INIT=$(( $INIT + 1 ))
          if [[ $INIT -ge $MAX_RETRY ]];then
              echo "The max retry has been reached, exit post_check_after_migration"
              exit 1
          fi
          sleep $DETECT_INTERVAL
          END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
          python3 get_prom_metrics.py -q 'topk(15,group_kind:apiserver_watch_events_sizes_sum:rate1m)' -s $START_TIME -e $END_TIME -t fullQ
          python3 get_prom_metrics.py -q 'container_memory_rss{container=~"kube-apiserver|kube-apiserver-cert-regeneration-controller|kube-apiserver-cert-syncer", pod=~"kube-apiserver.*", namespace="openshift-kube-apiserver"}' -s $START_TIME -e $END_TIME -t fullQL
          python3 get_prom_metrics.py -q 'topk(15, cluster_quantile:apiserver_request_duration_seconds:histogram_quantile{job="apiserver",quantile="0.9", subresource=""})' -s $START_TIME -e $END_TIME -t getInfo
          python3 get_prom_metrics.py -q 'histogram_quantile(0.99, sum by(le, service, verb) (rate(rest_client_request_duration_seconds_bucket{job=~"kube-controller-manager|scheduler|check-endpoints|kubelet"}[5m])))' -s $START_TIME -e $END_TIME -t bucket
          python3 get_prom_metrics.py -q 'apiserver_request_total{job="apiserver", system_client!="",resource!=""}' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'apiserver_watch_events_total' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'apiserver_cache_list_total{job="apiserver"}' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'apiserver_watch_cache_events_received_total' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'apiserver_watch_cache_events_dispatched_total' -s $START_TIME -e $END_TIME -t rate

          python3 get_prom_metrics.py -q 'ovnkube_node_workqueue_adds_total' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'ovnkube_controller_workqueue_retries_total' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'ovnkube_controller_resource_update_total' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'sum by(command, pod) (rate(ovnkube_node_cni_request_duration_seconds_bucket[5m]))' -s $START_TIME -e $END_TIME -t bucket

          python3 get_prom_metrics.py -q 'kubelet_http_requests_total' -s $START_TIME -e $END_TIME -t rate 
          python3 get_prom_metrics.py -q 'etcd_requests_total' -s $START_TIME -e $END_TIME -t rate
          python3 get_prom_metrics.py -q 'kube_state_metrics_watch_total' -s $START_TIME -e $END_TIME -t rate   
          python3 get_prom_metrics.py -q 'topk(10,sum(ALERTS{severity!="none"}) by (alertname, severity))' -s $START_TIME -e $END_TIME -t fullQL
          python3 get_prom_metrics.py -q 'sum(kube_pod_status_phase{}) by (phase)' -s $START_TIME -e $END_TIME -t getInfo

    done
}

