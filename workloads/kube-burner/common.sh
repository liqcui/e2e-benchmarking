#!/usr/bin/env bash
set -m
#set -x
source ../../utils/common.sh
source env.sh


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

function generated_egress_firewall_policy(){

  EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=${EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH:=""}
  if [[ -z $EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH ]];then
	echo "Please specify EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH for template path and file name"
	exit 1
  fi
  EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM=${EGRESS_FIREWALL_POLICY_TOTAL_NUM:="130"}
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
  EGRESS_FIREWALL_POLICY_RULE_TYPE_SUBNUM=$(( ($EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM - 5) /5 ))
  if [[ $EGRESS_FIREWALL_POLICY_RULE_TYPE_SUBNUM -ge 254 ]];then
        EGRESS_FIREWALL_POLICY_RULE_IP_NUM=${EGRESS_FIREWALL_POLICY_IP_NUM:="254"}
  else
	EGRESS_FIREWALL_POLICY_RULE_IP_NUM=$EGRESS_FIREWALL_POLICY_RULE_TYPE_SUBNUM
  fi
        EGRESS_FIREWALL_POLICY_RULE_DNS_NUM=$(( $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM - 5 - 2 * $EGRESS_FIREWALL_POLICY_RULE_IP_NUM))

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
   for ((i=0;i<=30;i++))
   do
       NEWACL=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl --no-leader-only --columns=_uuid list acl | grep ^_uuid | wc -l'`;
       NEW_MATCH_ACL=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c 'ovn-nbctl --no-leader-only --columns=match list acl | grep -c ^match'`;
       if [[ $NEWACL -ne $ACL && $NEWACL -eq $NEW_MATCH_ACL ]];then
           export ACL=$NEWACL
           export MATCH_ACL=$NEW_MATCH_ACL
           break
       fi
       echo -n "."&&sleep 1
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
   for ns in `oc get ns |grep anp| awk '{print $1}'|tail -50`
   do
      EGRESS_RULES_NUMS=`oc -n openshift-ovn-kubernetes exec -c northd $OVNKUBE_NODE_POD -- sh -c "ovn-nbctl --format=table --no-heading --columns=action,priority,match find acl external_ids:k8s.ovn.org/name=${ns}|wc -l"`;
      EGRESS_RULES_LIST+=(${ns}:${EGRESS_RULES_NUMS})
   done
   export EGRESS_RULES_NUMS_BY_NS=${EGRESS_RULES_LIST[*]}
   echo $EGRESS_RULES_NUMS_BY_NS | tr " " "\n"
}

function generated_anp_cidr_selector_multi_ips_multi_rules_multipolicy_bytenant(){
    #Create multiple anp
    #Each ANP contains multi rules
    #25 IPs per rule 
    SOURCE_NS_PREFIX=$1
    TARGET_NS_PREFIX=$2
    TOTAL_NS_BY_TA=${TOTAL_NS_BY_TA:=5}
    TOTAL_IP_BLOCK_NUM_BY_RULE=${TOTAL_IP_BLOCK_NUM_BY_RULE:=5}    
    PRIORITY=0 #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress

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
                 echo "No target ns was found inside generated_anp_cidr_selector_multi_ips_multi_rules_multipolicy_bytenant, please check"
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
                        #echo -e "  - name: \"deny-egress-to-anp-open-network-${RULE_INDEX}\"\n    action: \"Deny\"\n    ports:\n      - portNumber:\n          port: 5432\n          protocol: TCP\n      - portNumber:\n          port: 60000\n          protocol: TCP\n      - portNumber:\n          port: 9099\n          protocol: TCP\n      - portNumber:\n          port: 9393\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                        echo -e "  - name: \"allow-egress-to-anp-open-network-${APP_RULE_INDEX}\"\n    action: \"Allow\"\n    ports:\n      - portNumber:\n          port: 8080\n          protocol: TCP\n      - portRange:\n          start: 9201\n          end: 9205\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                        #echo -e "  - name: \"deny-egress-to-anp-open-network-${APP_RULE_INDEX}\"\n    action: \"Deny\"\n    ports:\n      - portNumber:\n          port: 5432\n          protocol: TCP\n      - portNumber:\n          port: 60000\n          protocol: TCP\n      - portNumber:\n          port: 9099\n          protocol: TCP\n      - portNumber:\n          port: 9393\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                        
                     fi
                     #echo sed -i "/allow-egress-to-anp-open-network-${APP_RULE_INDEX}/{n;n;n;n;n;n;n;n;n;n;n;s/$/\n      - ${APP_POD_IP}\/32/;}" ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     sed -i "/allow-egress-to-anp-open-network-${APP_RULE_INDEX}/{n;n;n;n;n;n;n;n;n;n;n;s/$/\n      - ${APP_POD_IP}\/32/;}" ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     #echo -e "      - ${APP_POD_IP}/32">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     
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
                        #echo -e "  - name: \"deny-egress-to-anp-open-network-${RULE_INDEX}\"\n    action: \"Deny\"\n    ports:\n      - portNumber:\n          port: 5432\n          protocol: TCP\n      - portNumber:\n          port: 60000\n          protocol: TCP\n      - portNumber:\n          port: 9099\n          protocol: TCP\n      - portNumber:\n          port: 9393\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                        #echo -e "  - name: \"allow-egress-to-anp-open-network-${DB_RULE_INDEX}\"\n    action: \"Allow\"\n    ports:\n      - portNumber:\n          port: 8080\n          protocol: TCP\n      - portRange:\n          start: 9201\n          end: 9205\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                        echo -e "  - name: \"deny-egress-to-anp-open-network-${DB_RULE_INDEX}\"\n    action: \"Deny\"\n    ports:\n      - portNumber:\n          port: 5432\n          protocol: TCP\n      - portNumber:\n          port: 60000\n          protocol: TCP\n      - portNumber:\n          port: 9099\n          protocol: TCP\n      - portNumber:\n          port: 9393\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     fi
                     #echo sed -i "/deny-egress-to-anp-open-network-${DB_RULE_INDEX}/{n;n;n;n;n;n;n;n;n;n;n;n;n;n;n;n;s/$/\n      - ${DB_POD_IP}\/32/;}" ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     sed -i "/deny-egress-to-anp-open-network-${DB_RULE_INDEX}/{n;n;n;n;n;n;n;n;n;n;n;n;n;n;n;n;s/$/\n      - ${DB_POD_IP}\/32/;}" ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     #echo -e "      - ${DB_POD_IP}/32">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-tenant${TENANT_ID}-p${PRIORITY}.yaml
                     
                     DB_POD_INIT=$(( $DB_POD_INIT + 1 ))
                 else
                    echo "Invalid Pod Type ..."
                    exit 1
                 fi
                
            done
            NS_INIT=$(( $NS_INIT + 1 ))
    done

    #oc -n openshift-kube-apiserver get pods -owide |grep kube-apiserver | awk '{print $6}'
    export TEST_STEP="Creating $TOTAL_ANP Multi ANP with Multi Rule/25 IP Per Rule"
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`    
    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-cidr-open-network-*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done
    echo "---------------------------------------------------------------------------------"
    oc get anp | grep allow-traffic-cidr-anp-open-network-tenant
    export TOTAL_ANP=`oc get anp | grep allow-traffic-cidr-anp-open-network-tenant|wc -l`
    echo "---------------------------------------------------------------------------------"
    echo "The total anp is $TOTAL_ANP"
    echo
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    get_ovn_node_system_usage_info

    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
}

function generated_anp_based_on_node_selector_with_multi_policy_by_ns(){
    
    TARGET_NS_PREFIX=$1
    PRIORITY=70  #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
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
         oc label ns $ns customer_tenat=tenant${TENANT_ID}      

         if [[ $PRIORITY -lt 0 || $PRIORITY -gt 99 ]];then
              echo "Limited the priority $PRIORITY between 0 to 99"
              break
         fi

         if [[ $INIT -gt $LABEL_NUM ]];then
              #reset INTI to 1
              INIT=1
         fi
        
         if [[ $IF_NEW_POLICY -eq 0 ]];then
         echo customer_tenat=tenant${TENANT_ID} node-role.kubernetes.io/allow-egress=n$NODE_INDEX 30003 true >>${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
         echo customer_tenat=tenant${TENANT_ID} node-role.kubernetes.io/deny-egress=n$NODE_INDEX 30003 false >>${WORKLOAD_TEMPLATE_PATH}/map-tenant-label.lst
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
          customer_tenat: tenant${TENANT_ID}
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
    export TEST_STEP="Creating ${TOTAL_ANP} Node Selector ANP/1 ANP Per 4 NS(1 Tenant)"      
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

function generated_anp_technical_assert_multi_rules_master_cards(){
    #Create multiple anp
    #Each ANP contains multi rules
    #25 IPs per rule 
    SOURCE_NS_PREFIX=$1
    TARGET_NS_PREFIX=$2
    TOTAL_NS_BY_TA=${TOTAL_NS_BY_TA:=5}
    TOTAL_IP_BLOCK_NUM_BY_RULE=${TOTAL_IP_BLOCK_NUM_BY_RULE:=5}    
    PRIORITY=0 #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress

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
            #TENANT_STEP=$(( $NS_INIT / $TOTAL_NS_BY_TA ))
            if [[ $IF_NEW_TENANT -eq 0 ]];then
                  TENANT_ID=$(( $TENANT_ID + 1 ))
                  PRIORITY=$(( $PRIORITY + 1 ))
                  echo PRIORITY is $PRIORITY
                  if [[ $PRIORITY -gt 99 ]];then
                       #reset PRIORITY to 1
                       PRIORITY=1
                  fi
            fi
            if [[ $IF_NEW_TENANT -eq 0 ]];then                   
cat>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-multi-tenant${TENANT_ID}-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-multi-techincal-asserts-anp-tenant${TENANT_ID}-p${PRIORITY}
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
  - name: "all-ingress-to-same-tenat"  
    action: Allow   # Allows connection   
    to:
    - namespaces:
        # namespaceSelector:
        matchLabels:
          customer_tenat: tenant${TENANT_ID}   
EOF
            fi            
            if [[ $NS_INIT -eq 0 ]];then
                export TEST_STEP="Add first DA namespaces to the first TA"
                export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
                oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
                echo oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
                oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite
                echo oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite
                get_ovn_node_system_usage_info
            elif [[ $NS_INIT -eq $TOTAL_NS_BY_TA ]];then
                export TEST_STEP="Add multiple DA namespaces to the first TA"
                export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`               
                oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
                echo oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
                oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite
                echo oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite
            else
                oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
                echo oc label ns $sns customer_tenat=tenant${TENANT_ID}  --overwrite
                oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite
                echo oc label ns $tns customer_tenat=tenant${TENANT_ID}  --overwrite                
            fi

            if [[ -z $tns ]];then
                 echo "No target ns was found inside generated_anp_cidr_selector_multi_ips_multi_rules_multipolicy_bytenant, please check"
            fi
            NS_INIT=$(( $NS_INIT + 1 ))         
    done
    get_ovn_node_system_usage_info
    #oc -n openshift-kube-apiserver get pods -owide |grep kube-apiserver | awk '{print $6}'
    export TEST_STEP="Creating $TOTAL_ANP Multi ANP with $TOTAL_NS_BY_TA NS Per TA"
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`    
    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-multi-tenant*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done
    echo "---------------------------------------------------------------------------------"
    oc get anp | grep allow-traffic-multi-techincal-asserts-anp
    export TOTAL_ANP=`oc get anp | grep allow-traffic-multi-techincal-asserts-anp|wc -l`
    echo "---------------------------------------------------------------------------------"
    echo "The total anp is $TOTAL_ANP"
    echo
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    get_ovn_node_system_usage_info

    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
}

function create_configmap_to_override_logging_level(){
  awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
  echo "Enable ACL Audit Logging ...."
  awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
  export TEST_STEP="Enable ACL Logging."
  export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`  
  oc annotate banp default k8s.ovn.org/acl-logging='{ "deny": "alert", "allow": "alert", "pass" : "warning" }'
  for anpName in `oc get anp |grep -v NAME | awk '{print $1}'`
  do
     oc annotate anp $anpName k8s.ovn.org/acl-logging='{ "deny": "alert", "allow": "alert", "pass" : "warning" }'
  done
  export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
  get_ovn_node_system_usage_info 
  #sleep 1800
#   awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}'
#   echo "Enable Debug Logging ...."
#   awk 'BEGIN{for(c=0;c<80;c++) printf "="; printf "\n"}' 
#   export TEST_STEP="Enable DEBUG Logging."
#   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
#      WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress                   
# cat>${WORKLOAD_TEMPLATE_PATH}/env-overrides.yaml<<EOF
# kind: ConfigMap
# apiVersion: v1
# metadata:
#   name: env-overrides
#   namespace: openshift-ovn-kubernetes
# data:
#   _master: | 
#     # This sets the log level for the ovn-kubernetes master process as well as the ovn-dbchecker:
#     OVN_KUBE_LOG_LEVEL=5
#     # You might also/instead want to enable debug logging for northd, nbdb and sbdb on all masters:
#     OVN_LOG_LEVEL=dbg
# EOF
#    for workerNode in `oc get nodes |grep worker| awk '{print $1}'`
#    do
#       echo -e "  ${workerNode}: |\n    OVN_KUBE_LOG_LEVEL=5\n    OVN_LOG_LEVEL=dbg"       
#    done
#    oc apply -n openshift-ovn-kubernetes -f ${WORKLOAD_TEMPLATE_PATH}/env-overrides.yaml
#    for ovnNodePods in `oc -n openshift-ovn-kubernetes get pods |grep ovnkube-node| awk '{print $1}'`
#    do
#        oc -n openshift-ovn-kubernetes delete pod $ovnNodePods
#        sleep 10
#    done
#    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
#    get_ovn_node_system_usage_info 
}


function check_traffic_to_internet(){
    SOURCE_NS_PREFIX=$1
    EXPECTED_RESULT=$2
    echo SOURCE_NS_FILTER is $SOURCE_NS_FILTER in check_traffic_to_internet
    echo TARGET_NS_FILTER is $TARGET_NS_FILTER in check_traffic_to_internet
    if [[ -z $SOURCE_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX or SOURCE_NS_PREFIX
            exit 1
    fi

    SOURCE_NS=`oc get ns |grep -w $SOURCE_NS_PREFIX | awk '{print $1}'| head -1`
    if [[ -z $SOURCE_NS ]];then
            echo "No SOURCE_NS $SOURCE_NS was found"
            exit 1
    fi
    echo "check SOURCE_POD in $SOURCE_NS inside check_traffic_to_internet"
    SOURCE_POD=`oc -n $SOURCE_NS get pods|grep ef| head -1 | awk '{print $1}'`
    if [[ -z $SOURCE_POD ]];then
            echo "No SOURCE_POD was found"
            exit 1
    fi
    echo SOURCE_NS is $SOURCE_NS
    echo SOURCE_POD is $SOURCE_POD

    
    for ipaddr in 8.8.8.8 1.1.1.1
    do
        oc -n $SOURCE_NS exec -i $SOURCE_POD -- ping -c2 $ipaddr
        #oc -n $SOURCE_NS exec -it $SOURCE_POD -- curl -Is $pod_id:8080 --connect-timeout 5
       
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
         echo "check the ef pod in $ns inside check_traffic_to_labeled_node_host"
         SOURCE_POD=`oc -n $ns get pods|grep ef| head -1 | awk '{print $1}'`
         if [[ -z $SOURCE_POD ]];then
            echo "No SOURCE_POD was found"
            exit 1
         fi
         echo SOURCE_NS is $ns
         echo SOURCE_POD is $SOURCE_POD
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

function check_if_pods_is_ready(){
   NS_NAME=$1
   RS_TYPE=$2
   RS_NAME=$3

   INIT=1
   MAXRETRY=20
   while [[ $INIT -le $MAXRETRY ]];
   do
        if [[ $RS_TYPE == "daemonset" ]];then
           desiredPods=`oc -n $NS_NAME get daemonset $RS_NAME -ojsonpath='{.status.desiredNumberScheduled}'`
           readyPods=`oc -n $NS_NAME get daemonset $RS_NAME -ojsonpath='{.status.numberReady}'`
        elif [[ $RS_TYPE == "deployment" ]];then
           desiredPods=`oc -n $NS_NAME get deployment $RS_NAME -ojsonpath='{.spec.replicas}'`
           readyPods=`oc -n $NS_NAME get deployment $RS_NAME -o=jsonpath='{.status.readyReplicas}'`
        fi
        notReadyPods=`oc -n $NS_NAME get pods | grep '0/.'|wc -l`
        if [[ $readyPods -eq $desiredPods && $notReadyPods -eq 0 ]];then
		        echo "All deployment/daemonset $RS_NAME pod in $NS_NAME is ready"
		        break
	      fi

	      sleep 30
	      if [[ $INIT -lt $MAXRETRY ]];then
	          echo "Some deployment/daemonset $RS_NAME pod in $NS_NAME isn't ready, continue to check"
        else
            for podname in `oc get pods -n $NS_NAME -oname`
            do
               oc -n $NS_NAME describe $podname |grep -i -E 'FailedCreatePodSandBox|failed to configure pod interface|timed out waiting for OVS port binding'
	      	  done
            echo "The retry time reach maxinum, exit"
	      	  exit 1
        fi
	      INIT=$(( $INIT + 1 ))
   done
}

function create_and_delete_anp_network_policy(){
   WORKLOAD_TMPLATE_PATH=workloads/large-networkpolicy-egress
   echo "create recycle ns to simulate customer remove network policy and egressfirewall operation" 

   export TEST_STEP="Creating recycle ns with large network policy"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
  
   i=1
   while [[ $i -le 100 ]]
   do
	      oc create ns recycle-ns${i}
	      oc -n recycle-ns${i} apply -f ${WORKLOAD_TMPLATE_PATH}/deny-all.yml
        oc -n recycle-ns${i} apply -f ${WORKLOAD_TMPLATE_PATH}/networkpolicy-essential-ports.yml
        oc -n recycle-ns${i} apply -f $EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH
	      i=$(( $i + 1 ))
   done
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
   get_ovn_node_system_usage_info   
   sleep 600

   export TEST_STEP="Creating recycle ns with large network policy[3Min]"  
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`    
   get_ovn_node_system_usage_info

   echo "remove network policy and egressfirewall operation" 
   export TEST_STEP="Deleting recycle ns with large network policy"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`   
   oc get ns |grep recycle-ns | awk '{print $1}'| xargs oc delete ns
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
   get_ovn_node_system_usage_info

   sleep 180
   export TEST_STEP="Deleting recycle ns with large network policy[3Min]"  
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`    
   get_ovn_node_system_usage_info
}

function networkPolicyInitSyncDurationCheck(){
   #Check If existing pod is running
   UUID=${UUID:=""}
   WAIT_OVN_DB_SYNC_TIME=${WAIT_OVN_DB_SYNC_TIME:=""}
   WORKLOAD_TMPLATE_PATH=workloads/large-networkpolicy-egress
   INIT=1
   MAXRETRY=240
   while [[ $INIT -le $MAXRETRY ]];
   do
	      unreadyNum=`oc get pods -A |grep $UUID | awk '{print $3}' | grep '0/.'|wc -l`
        if [[ $unreadyNum -eq 0 ]];then
		       echo "All previous large networkpolicy egress job pod in $UUID is ready"
		       break
	      fi
	      sleep 30

	      if [[ $INIT -lt $MAXRETRY ]];then
	           echo "Some large networkpolicy egress job pod in $UUID isn't ready, continue to check"
        else
		         echo "The retry time reach maxinum, exit"
		         exit 1
        fi
	      INIT=$(( $INIT + 1 ))
   done
   echo "After enable banp anp and network policy"
   create_and_delete_anp_network_policy

   if ! oc get ns |grep -w zero-trust-jks >/dev/null;
   then
      oc create ns zero-trust-jks;
   fi  
   if ! oc get ns |grep -w zero-trust-clt >/dev/null;
   then
      oc create ns zero-trust-clt;
   fi

   export TEST_STEP="Creating 3 netpol in zero-trust-jks with large scale netpol/egrss firewall"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
   oc -n zero-trust-jks apply -f ${WORKLOAD_TMPLATE_PATH}/deny-all.yml
   oc -n zero-trust-jks apply -f ${WORKLOAD_TMPLATE_PATH}/probe-detect-nginx.yaml
   oc -n zero-trust-jks apply -f ${WORKLOAD_TMPLATE_PATH}/probe-detect-service.yaml
   oc -n zero-trust-jks apply -f ${WORKLOAD_TMPLATE_PATH}/networkpolicy-essential-ports.yml
   oc -n zero-trust-jks apply -f ${WORKLOAD_TMPLATE_PATH}/networkpolicy-allowdns.yml
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`      
   get_ovn_node_system_usage_info   

   echo "wait for $WAIT_OVN_DB_SYNC_TIME seconds to make sure all network policy/egress firewall rule sync"
   sleep $WAIT_OVN_DB_SYNC_TIME

   export TEST_STEP="Creating deny all networkpolicy in zero-trust-clt"   
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
   oc -n zero-trust-clt apply -f ${WORKLOAD_TMPLATE_PATH}/deny-all.yml
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
   get_ovn_node_system_usage_info   

   sleep 180
   export TEST_STEP="Creating deny all networkpolicy in zero-trust-clt[3Min]"
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
   get_ovn_node_system_usage_info

   export TEST_STEP="Creating 3 networkpolicy in zero-trust-clt"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
   oc -n zero-trust-clt apply -f ${WORKLOAD_TMPLATE_PATH}/probe-detect-deploy.yaml
   oc -n zero-trust-clt apply -f ${WORKLOAD_TMPLATE_PATH}/networkpolicy-essential-ports.yml
   oc -n zero-trust-clt apply -f ${WORKLOAD_TMPLATE_PATH}/networkpolicy-allowdns.yml
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`   
   get_ovn_node_system_usage_info

   export TEST_STEP="Scaling Pod in zero-trust-clt with large sale netpol/egressfirewall"
   export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
   EXPECT_RPLICAS=`oc get nodes |grep worker |wc -l`
   oc -n zero-trust-clt scale  deployment/probe-detect-deploy --replicas=${EXPECT_RPLICAS}
   check_if_pods_is_ready zero-trust-clt deployment probe-detect-deploy
   export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`   
   get_ovn_node_system_usage_info
   echo "----------------------`date`-------------------------------"
}

function get_ovn_node_system_usage_info(){
   echo "----------------------TOP 15 Usage of Containers---------------------------"
   oc -n openshift-ovn-kubernetes adm top pods --containers| sort -n -r -k4 | head -15

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

   echo "----------------------TOP Usage of Worker Node---------------------------"
   oc adm top nodes | grep -i -E -v "$masterNodeNames|$infraNodeNames" | sort -k5 -n
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

function check_traffic_between_anp_zones(){
    
    SOURCE_NS=$1
    TARGET_NS=$2
    PORT_NUMBER=$3
    EXPECTED_RESULT=$4

    if [[ -z $TARGET_NS || -z $SOURCE_NS ]];then
            echo please specify TARGET_NS_FILTER or SOURCE_NS_FILTER
            exit 1
    fi

    TARGET_NS=`oc get ns |grep -w $TARGET_NS | awk '{print $1}'|head -10`
    if [[ -z $TARGET_NS ]];then
            echo "No TARGET_NS was found"
            exit 1
    fi

    SOURCE_NS=`oc get ns |grep -w $SOURCE_NS | awk '{print $1}'| head -1`
    if [[ -z $SOURCE_NS ]];then
            echo "No SOURCE_NS was found"
            exit 1
    fi

    SOURCE_POD=`oc -n $SOURCE_NS get pods|grep ef| head -1 | awk '{print $1}'`
    echo "find SOURCE_POD $SOURCE_POD in $SOURCE_NS inside check_traffic_between_anp_zones "
    if [[ -z $SOURCE_POD ]];then
            echo "No SOURCE_POD was found"
            exit 1
    fi
    echo SOURCE_NS is $SOURCE_NS
    echo SOURCE_POD is $SOURCE_POD
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

function create_client_pod_to_access_labeled_node_ports(){    
        NS_NAME_FILTER=$1
        NODE_LABEL=$2
        EXPECT_RPLICAS=$3
        export WORKER_NODE_IPs=`oc get nodes -l${NODE_LABEL} -ojsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{" "}'`

        for ns in `oc get ns |grep -w $NS_NAME_FILTER | awk '{print $1}'`
        do
           echo "Create anp node traffic client deployment node-traffic-clt in $ns"
           echo "--------------------------------------------------------------------"
           envsubst '$WORKER_NODE_IPs'< ${WORKLOAD_TEMPLATE_PATH}/anp-node-traffic-deployment.yaml | oc -n $ns apply -f-
           echo scale deployment/node-traffic-clt to ${EXPECT_RPLICAS} replicas
           oc scale deployment/node-traffic-clt --replicas=${EXPECT_RPLICAS} -n $ns
           echo "--------------------------------------------------------------------"
           check_if_pods_is_ready $ns deployment node-traffic-clt
        done
}

function create_ingress_traffic_pods(){    
        EXPECT_RPLICAS=$1
        export INGRESS_ROUTES=`oc get route -A|grep perfweb-ingress-traffic-service | awk '{print $3}'| tr -s "\n" " "`
        oc create ns anp-ingress-traffic
        envsubst '$INGRESS_ROUTES'< ${WORKLOAD_TEMPLATE_PATH}/ingress-traffic-app.yaml | oc -n anp-ingress-traffic apply -f-
        
        echo scale deployment/ingress-traffic-testing to ${EXPECT_RPLICAS} replicas
        oc scale deployment/ingress-traffic-testing --replicas=${EXPECT_RPLICAS} -n anp-ingress-traffic
        echo "--------------------------------------------------------------------"
        check_if_pods_is_ready anp-ingress-traffic deployment ingress-traffic-testing
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
 
    echo "#########################################################################"
    echo "#        ${DENY_OR_ALLOW} traffic $SOURCE_NS to $TARGET_NS zones     #"
    echo "#########################################################################"
    echo "Verify the traffic between $SOURCE_NS and $TARGET_NS zones"
    check_traffic_between_anp_zones $SOURCE_NS $TARGET_NS $PORT_NUMBER $EXPECTED_RESULT
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
    echo "Verify the traffic between $TARGET_NS and $SOURCE zones"
    echo "#########################################################################"
    echo "#      ${DENY_OR_ALLOW} traffic $TARGET_NS to $SOURCE_NS zones    #"
    echo "#########################################################################"  
    check_traffic_between_anp_zones $TARGET_NS $SOURCE_NS $PORT_NUMBER $EXPECTED_RESULT
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
    echo NODE_LABEL is $NODE_LABEL inside format_Output_ANP_BANP_Source2Host
    echo "#########################################################################"
    echo "#        ${DENY_OR_ALLOW} traffic $SOURCE_NS to $PORT_NUMBER of node host ip         #"
    echo "#########################################################################"
    echo "Verify the traffic between $SOURCE_NS and target node host ip"
    check_traffic_to_labeled_node_host $SOURCE_NS "$NODE_LABEL" $PORT_NUMBER $EXPECTED_RESULT
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
    ANP_NAME=`grep -A2 "metadata:" $YAMLFILE | grep "name:" | awk '{print $2}'`
  
    if [[ -z $ANP_NAME ]];then
        echo no ANP_NAME was found
    else
        oc get banp | grep -w $ANP_NAME>/dev/null
        RC1=$?
        oc get anp | grep -w $ANP_NAME>/dev/null
        RC2=$?

      	if [[ $RC1 -eq 0 ]]; then
             oc get banp $ANP_NAME -oyaml |grep SetupFailed >/dev/null
             if [[ $? -eq 0 ]];then
                echo "BANP setup failed, please check"
                oc get banp default -ojsonpath={.status}| jq
                exit 1
             fi
        elif [[ $RC2 -eq 0 ]]; then
             oc get anp $ANP_NAME -oyaml |grep SetupFailed >/dev/null
             if [[ $? -eq 0 ]]; then
                echo "ANP setup failed, please check"
                oc get anp $ANP_NAME -ojsonpath={.status}| jq
                exit 1
             fi
        fi
    fi   
}

function create_anp_allow_egress_api(){
    TARGET_NS_LIST=$1
    PRIORITY=9
    for TARGET_NS in `echo $TARGET_NS_LIST`
    do
cat>${WORKLOAD_TEMPLATE_PATH}/9_anp_allow-traffic-egress-kube-apiserver-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-egress-to-kubeapi-${TARGET_NS}-p${PRIORITY}
spec:
  priority: ${PRIORITY}
  subject:
    namespaces:
      namespaces: {}
  egress:
  - name: "allow-egress-to-kube-apiserver"
    action: "Allow"
    ports:
    - portNumber:
        port: 6443
        protocol: TCP
    - portNumber:
        port: 443
        protocol: TCP           
    to:
    - networks:
      - 172.30.0.0/16
  # egress:
  # - name: "allow-to-API-server"
  #   action: "Allow"
  #   to:
  #   - nodes:
  #      matchExpressions:
  #      - key: node-role.kubernetes.io/control-plane
  #        operator: Exists
  #   ports:
  #   - portNumber:
  #       port: 6443
  #       protocol: TCP 
  #   - portNumber:
  #       port: 443
  #       protocol: TCP                       
EOF
         for pod_name in `oc -n openshift-kube-apiserver get pods |grep kube-apiserver | awk '{print $1}'`
         do
             pod_ip=`oc -n openshift-kube-apiserver get pods $pod_name -ojsonpath={.status.podIP}`
             echo -e "    - networks:\n      - ${pod_ip}/32">>${WORKLOAD_TEMPLATE_PATH}/9_anp_allow-traffic-egress-kube-apiserver-p${PRIORITY}.yaml
         done
         PRIORITY=$(( $PRIORITY -1 ))
    done

    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/9_anp_allow-traffic-egress-kube-apiserver-*.yaml`
    do
       oc apply -f $yamlfile
       printYAMLFile  $yamlfile   
    done
}

function label_node_for_allow_deny_egress_nodes(){

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

function unlabel_all_nodes(){
     for node in `oc get nodes -lnode-role.kubernetes.io/worker= -oname`
     do
         oc label $node node-role.kubernetes.io/allow-egress- --overwrite
         oc label $node node-role.kubernetes.io/deny-egress- --overwrite
     done
}

function create_anp_banp_verify_traffic_between_different_zones(){

    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-restricted"
    #export TEST_STEP="Creating 14 POD Selector ANP to deny egress/ingress policy[Min]."
    #export TEST_STEP="Creating 1 POD Selector ANP of No Traffic Between Test and Restricted."
    #export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of No Traffic Between Test and Restricted."      
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/02_anp_no-traffic-test-restricted-p39.yaml   
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/02_anp_no-traffic-test-restricted-p39.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-unknown"
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-restricted"
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # export TEST_STEP="Creating 1 POD Selector ANP of No traffic between unknown and Restricted."
    echo "Creating 1 POD Selector ANP of No traffic between unknown and Restricted."       
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/03_anp_no-traffic-unknown-restricted-p38.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/03_anp_no-traffic-unknown-restricted-p38.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false    

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-open"
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # export TEST_STEP="Creating 1 POD Selector ANP of No traffic between test and unknown."
    echo "Creating 1 POD Selector ANP of No traffic between test and unknown."     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/04_anp_no-traffic-test-unknown-p37.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/04_anp_no-traffic-test-unknown-p37.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false   

    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-unknown"
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    # export TEST_STEP="Creating 1 POD Selector ANP of allowing ingress only between test and unknown."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allowing ingress only between test and unknown."     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/05_anp_allow-ingress-only-test-unknown-p36.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/05_anp_allow-ingress-only-test-unknown-p36.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true   

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    # export TEST_STEP="Creating 1 POD Selector ANP of allowing egress only between test and unknown."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allowing egress only between test and unknown."     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/06_anp_allow-egress-only-test-unknown-p35.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/06_anp_allow-egress-only-test-unknown-p35.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
  
    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    # export TEST_STEP="Creating 1 POD Selector ANP of no traffic between unknown and open."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of no traffic between unknown and open."      
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/07_anp_no-traffic-unknown-open-p34.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/07_anp_no-traffic-unknown-open-p34.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    # export TEST_STEP="Creating 1 POD Selector ANP of ingress only between unknown and open."    
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of ingress only between unknown and open."    
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/08_anp_allow-ingress-only-unknown-open-p33.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/08_anp_allow-ingress-only-unknown-open-p33.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
  
    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    # export TEST_STEP="Creating 1 POD Selector ANP of egress only between unknown and open."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of egress only between unknown and open."     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/09_anp_allow-egress-only-unknown-open-p32.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/09_anp_allow-egress-only-unknown-open-p32.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
  
    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    # export TEST_STEP="Creating 1 POD Selector ANP of no traffic between open and test."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of no traffic between open and test."      
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/10_anp_no-traffic-open-test-p31.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/10_anp_no-traffic-open-test-p31.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    # export TEST_STEP="Creating 1 POD Selector ANP of allow ingress between open and test."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allow ingress between open and test."    
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/11_anp_allow-ingress-only-open-test-p30.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/11_anp_allow-ingress-only-open-test-p30.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
  
    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    # export TEST_STEP="Creating 1 POD Selector ANP of allow egress between open and test."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allow egress between open and test."       
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/12_anp_allow-egress-only-open-test-p29.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/12_anp_allow-egress-only-open-test-p29.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false

    SOURCE_NS_FILTER="anp-open"
    TARGET_NS_FILTER="anp-test"
    # export TEST_STEP="Creating 1 POD Selector ANP of allow all traffic between open and test."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allow all traffic between open and test."     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/13_anp_allow-all-traffic-open-test-p28.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/13_anp_allow-all-traffic-open-test-p28.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-unknown"
    TARGET_NS_FILTER="anp-open"
    # export TEST_STEP="Creating 1 POD Selector ANP of allow all traffic between unknown and test."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allow all traffic between unknown and test."       
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/14_anp_allow-all-traffic-unknown-open-p27.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/14_anp_allow-all-traffic-unknown-open-p27.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true

    SOURCE_NS_FILTER="anp-test"
    TARGET_NS_FILTER="anp-unknown"
    # export TEST_STEP="Creating 1 POD Selector ANP of allow all traffic between test and unknown."
    # export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    echo "Creating 1 POD Selector ANP of allow all traffic between test and unknown."     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/15_anp_allow-all-traffic-test-unknown-p26.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/15_anp_allow-all-traffic-test-unknown-p26.yaml
    # export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
    # get_ovn_node_system_usage_info    
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
}

function create_anp_banp_cidr_verify_traffic_tween_different_zones(){
    
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
    SOURCE_NS_FILTER="anp-cidr"
    TARGET_NS_FILTER="anp-open"
    IF_MASTER_CARD_CASE=${IF_MASTER_CARD_CASE:="false"}


    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false

    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false

    if [[ $IF_MASTER_CARD_CASE == "false" ]];then

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
         check_traffic_to_internet $TARGET_NS_FILTER true
         echo "-------------------------------------------------------------------------"
    
         export TEST_STEP="Creating 1 CIDR ANP to Allow Egress to The Whole Cluster Network"
         export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`         
         oc apply -f ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-cluster-network-p20.yaml
         echo "-----The egress of $SOURCE_NS_FILTER open to all cluster network--------"
         printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-cluster-network-p20.yaml
         export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
         get_ovn_node_system_usage_info
     
         format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
         format_Output_ANP_BANP_Source2Target  $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false
     
         SOURCE_NS_FILTER="anp-cidr"
         TARGET_NS_FILTER="anp-test"
         format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
         format_Output_ANP_BANP_Target2Source  $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 true
     
         export TEST_STEP="Deleting 1 CIDR ANP to Allow Egress to The Whole Cluster Network"
         export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
         oc delete -f ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-cluster-network-p20.yaml
         export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`    
         get_ovn_node_system_usage_info    
         echo ----------------------------------------------------------
    fi
    
    generated_anp_cidr_selector_multi_ips_multi_rules_multipolicy_bytenant anp-cidr anp-open

    TOTAL_LINE=`cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst|head -100 |wc -l`
    for ((i=1;i<=$TOTAL_LINE;i++))
    do
        SOURCE_NS_FILTER=`sed -n "${i}p" ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst| awk '{print $1}'`
        TARGET_NS_FILTER=`sed -n "${i}p" ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst| awk '{print $2}'`
        format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
        format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false
    done

    SOURCE_NS_FILTER="anp-cidr"
    TARGET_NS_FILTER="anp-test"
    ########Should Block Connection From Other Tenant###################################
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source  $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false
}

function create_anp_banp_master_cards_verify_traffic_tween_different_zones(){
    
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
    SOURCE_NS_FILTER="anp-cidr"
    TARGET_NS_FILTER="anp-open"
    IF_MASTER_CARD_CASE=${IF_MASTER_CARD_CASE:="false"}


    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false

    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false

    echo "#########################################################################"
    echo "#        Dely traffic $SOURCE_NS_FILTER to internet zones               #"
    echo "#########################################################################"   
    echo "-------------------------------------------------------------------------"
    check_traffic_to_internet $SOURCE_NS_FILTER true
    echo "-------------------------------------------------------------------------"
    
    generated_anp_technical_assert_multi_rules_master_cards anp-cidr anp-open

    TOTAL_LINE=`cat ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst |wc -l`
    for ((i=1;i<=$TOTAL_LINE;i++))
    do
        SOURCE_NS_FILTER=`sed -n "${i}p" ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst| awk '{print $1}'`
        TARGET_NS_FILTER=`sed -n "${i}p" ${WORKLOAD_TEMPLATE_PATH}/map-ns-tenant.lst| awk '{print $2}'`
        format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 true
        format_Output_ANP_BANP_Source2Target $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 true
    done

 
    echo "#########################################################################"
    echo "#                Dely traffic between different TA                      #"
    echo "#########################################################################"
    echo "-------------------------------------------------------------------------"
    SOURCE_NS=`oc get ns -lcustomer_tenat=tenant1 |awk '{print $1}'| grep -v NAME| head -1`
    TARGET_NS=`oc get ns -lcustomer_tenat=tenant2 |awk '{print $1}'| grep -v NAME|head -1`

    format_Output_ANP_BANP_Source2Target $SOURCE_NS $TARGET_NS 8080 false
    format_Output_ANP_BANP_Source2Target $SOURCE_NS $TARGET_NS 5432 false
    echo "-------------------------------------------------------------------------"   

    SOURCE_NS_FILTER="anp-cidr"
    TARGET_NS_FILTER="anp-test"
    ########Should Block Connection From Other Tenant###################################
    format_Output_ANP_BANP_Target2Source $SOURCE_NS_FILTER $TARGET_NS_FILTER 8080 false
    format_Output_ANP_BANP_Target2Source  $SOURCE_NS_FILTER $TARGET_NS_FILTER 5432 false
}

function create_anp_banp_egress_rule_verify_traffic_from_two_different_groups_to_host(){
    
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress

    echo "-----The egress of $SOURCE_NS_FILTER deny to all node network--------"
    #################################Verify Default Policy of BANP##########################################
    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 10250 false
    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 30003 false

    format_Output_ANP_BANP_Source2Host $TARGET_NS_FILTER "node-role.kubernetes.io/worker" 10250 true
    format_Output_ANP_BANP_Source2Host $TARGET_NS_FILTER "node-role.kubernetes.io/worker" 30003 true

    SOURCE_NS_FILTER="anp-restricted"
    TARGET_NS_FILTER="anp-test"
    export TEST_STEP="Creating 1 Node Selector ANP to Allow Egress to Two Worker Nodes Gropus"
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    oc apply -f ${WORKLOAD_TEMPLATE_PATH}/19-anp_allow-traffic-egress-node-ns-p19.yaml
    printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/19-anp_allow-traffic-egress-node-ns-p19.yaml
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    get_ovn_node_system_usage_info

    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 30003 true
    format_Output_ANP_BANP_Source2Host $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" 10250 false    

    export TEST_STEP="Deleting the Node Selector ANP to Allow Egress to Two Worker Nodes Gropus"
    export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
    echo "Clean up old anp before apply new one"
    oc delete -f ${WORKLOAD_TEMPLATE_PATH}/19-anp_allow-traffic-egress-node-ns-p19.yaml
    export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`    
    get_ovn_node_system_usage_info

    export IF_LABEL_IN_ORDER="true"  
    label_node_for_allow_deny_egress_nodes 
    generated_anp_based_on_node_selector_with_multi_policy_by_ns $SOURCE_NS_FILTER
}

function check_if_machineset_ready(){
    DESIRED_REPLICAS=$1
    MAX_RETRT=360
    for((i=1;i<=$MAX_RETRT;i++))
    do
      AVAILABLE_REPLICAS=`oc -n openshift-machine-api get machineset $FIRST_MACHINESET_NAME -ojsonpath='{.status.readyReplicas}'`
      if [[ $AVAILABLE_REPLICAS -eq $DESIRED_REPLICAS ]];then
          echo -e "\nAll the node is ready, actual replicas is $AVAILABLE_REPLICAS\n"
    	  break
      else
    	  echo -n "."&&sleep 5
      fi
    done
}

function verify_if_mcp_be_in_updated_state_by_name() {
	
    MCP_NAME=$1
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
function scale_out_worker_nodes(){
       echo "Scaling out worker nodes ...."
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
       export ADDITIONAL_REPLICAS=${ADDITIONAL_REPLICAS:=1}
       #export FIRST_MACHINESET_NAME=`oc get machineset -n openshift-machine-api -oname| grep worker | head -1`
       export FIRST_MACHINESET_NAME=`oc get machineset -n openshift-machine-api | grep -w -v -E '0|NAME' | grep worker| awk '{print $1}'| head -1`
       export PREVIOUS_REPLICAS=`oc -n openshift-machine-api get machineset $FIRST_MACHINESET_NAME -ojsonpath='{.spec.replicas}'`
       export DESIRED_REPLICAS=$(( $PREVIOUS_REPLICAS + $ADDITIONAL_REPLICAS ))
       echo "Scale out $FIRST_MACHINESET_NAME from $PREVIOUS_REPLICAS to $DESIRED_REPLICAS"
       oc -n openshift-machine-api scale machineset $FIRST_MACHINESET_NAME --replicas=${DESIRED_REPLICAS}
       sleep 60
       check_if_machineset_ready ${DESIRED_REPLICAS}
       for((i=0;i<=600;i++))
       do
           WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name worker`
           if [[ $WORKER_MCP_STATUS == "true" ]];then
               echo The worker mcp is ready
                   break
            fi
               echo -n "."&&sleep 1;
       done

       
}

function scale_down_worker_nodes(){
      
       export ADDITIONAL_REPLICAS=${ADDITIONAL_REPLICAS:=1}
       export FIRST_MACHINESET_NAME=`oc get machineset -n openshift-machine-api | grep -w -v -E '0|NAME' | grep worker| awk '{print $1}'| head -1`
       export PREVIOUS_REPLICAS=`oc -n openshift-machine-api get machineset $FIRST_MACHINESET_NAME -ojsonpath='{.spec.replicas}'`
       export DESIRED_REPLICAS=$(( $PREVIOUS_REPLICAS - $ADDITIONAL_REPLICAS ))
       if [[ DESIRED_REPLICAS -lt 0 ]];then
           echo "No enough worker node to scale down"
           exit 1
       fi
       echo "Scaling down worker nodes ...."
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
       echo "Scale Down woker node from $PREVIOUS_REPLICAS to $DESIRED_REPLICAS"
       oc -n openshift-machine-api scale machineset $FIRST_MACHINESET_NAME --replicas=${DESIRED_REPLICAS}
       sleep 60
       check_if_machineset_ready ${DESIRED_REPLICAS}
       sleep 120    
}

function create_ingress_route(){

      if ! oc get route -A |grep perfweb-ingress-traffic-service; then
        echo "Create a route service to public network"
        for ns_name in `oc get ns |grep anp-cidr| awk '{print $1}'`
        do
           oc -n ${ns_name} create route edge --service=perfweb-ingress-traffic-service
        done
      fi
}

function scale_pods_replicas_with_anp(){
  ANP_NAMESPACE=$1
  POD_REPLICAS=$2
  DEPLOYMENTS=`oc -n $ANP_NAMESPACE get deployment | awk '{print $1}'`
  for deployment_name in $DEPLOYMENTS
  do 
      echo "scale $deployment_name to $POD_REPLICAS"
      echo oc -n $ANP_NAMESPACE scale deployment $deployment_name --replicas=$POD_REPLICAS
      echo check_if_pods_is_ready $ANP_NAMESPACE deployment $deployment_name

  done

}

function run_large_networkpolicy_egressfirewall_anp_workload(){
       IF_CIDR_ANP=${IF_CIDR_ANP:="false"}
       IF_NODE_ANP=${IF_NODE_ANP:="false"}
       IF_MASTER_CARD_CASE=${IF_MASTER_CARD_CASE:="false"}
       IF_RECYCLE_NODE=${IF_RECYCLE_NODE:="true"}
       WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress
       echo -e "Test Step,Create Time, Query Time, Max Master CPU,Max Master RAM,Max Worker CPU,Max Worker RAM,ACL,Match ACL,Port Group,Address Set,lflow-list, DumpFlows" > /tmp/system_resource_info.csv

       #################################Recycle Nodes Without Large Scale Pods######################################
       if [[ $IF_RECYCLE_NODE == "false" ]];then
             sleep 1800
             export TEST_STEP="Scaling Down Worker Nodes Without Large Scale PODs"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
             scale_down_worker_nodes
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
             get_ovn_node_system_usage_info
                
             sleep 300
             echo "Save old node name and ovn pod list to old-node-ovn-pods.lst"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
             oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst  
             echo    "#############   ocp-node-ovn-pods-old.lst  #############" 
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
             cat /tmp/ocp-node-ovn-pods-old.lst
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
             scale_out_worker_nodes
      
             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
             oc get nodes |grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
             echo "New worker node and ovn pods when scaling out worker node"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u 
             echo 
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u | tr -s "\n" "|"
             echo
      
             sleep 600
             export TEST_STEP="Restart OVN Node Pods Without Large Scale PODs and BANP/ANP/NetPol/EgressFW[Min]"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
             restartOVNPODs
       fi
  
       #sleep 1200
       ###################################Prepare Testing Environment#################################
       echo "Prepare Testing Environment for BANP and ANP - Creating NS and Pods - Mixed Scenario"
       awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

       #########################Creating Large Scale Pods##########################
       export TEST_STEP="Creating Large Scale PODs without BANP/ANP/NetPol/EgressFW[Min]"
       export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
       if [[ $IF_MASTER_CARD_CASE == "false" ]];then           
           echo "Create http server pods on each worker nodes in namespace anp-node-http"
           oc create ns anp-node-http
           oc -n anp-node-http apply -f workloads/large-networkpolicy-egress/anp-node-traffic-daemonset.yaml
           check_if_pods_is_ready anp-node-http daemonset node-traffic-httpsvr
           
           unlabel_all_nodes
       fi
       #for anptype in anp-restricted-pods anp-cidr-pods anp-open-pods anp-unknown-pods anp-test-pods
       if [[ $IF_MASTER_CARD_CASE == "true" ]];then     
             ANP_PODS="anp-master-cards-s-pods anp-master-cards-t-pods anp-test-pods"
       else
             ANP_PODS="anp-restricted-pods anp-cidr-pods anp-open-pods anp-unknown-pods anp-test-pods"
       fi

       for anptype in $ANP_PODS         
       do
            #EXPECT_RPLICAS used for scale node-traffic-clt
            NODE_TRAFFIC_CLT_EXPECT_RPLICAS=$POD_RPLICAS

            #This test case focus on nodeselector, we don't need to create too much pods on anp-test-x namespace
            #So try to create more pods on anp-restricted-x ns as possible. 
            
            if [[ $anptype == "anp-test-pods" ]];then
               export ANP_POD_RPLICAS=3
               export ANP_JOB_ITERATIONS=1
               #sed -i 's/namespacedIterations: true/namespacedIterations: false/g' workloads/large-networkpolicy-egress/case-large-networkpolicy-egress-${anptype}.yml
               #grep namespacedIterations workloads/large-networkpolicy-egress/case-large-networkpolicy-egress-${anptype}.yml
            fi
            WORKLOAD_TEMPLATE=workloads/large-networkpolicy-egress/case-large-networkpolicy-egress-${anptype}.yml
            run_workload
       done

       SOURCE_NS_FILTER="anp-restricted"
       TARGET_NS_FILTER="anp-test"

       if [[ $IF_MASTER_CARD_CASE == "false" ]];then     
           create_client_pod_to_access_labeled_node_ports $SOURCE_NS_FILTER "node-role.kubernetes.io/worker" $NODE_TRAFFIC_CLT_EXPECT_RPLICAS

       fi

       create_ingress_route 
       create_ingress_traffic_pods $POD_RPLICAS
       export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
       get_ovn_node_system_usage_info

       #################################Recycle Nodes With Large Scale Pods Without BANP/ANP/NetPol#########################       
       if [[ $IF_RECYCLE_NODE == "false" ]];then
             sleep 1800
             export TEST_STEP="Scaling Down Worker Nodes With Large Scale PODs without BANP/ANP/NetPol/EgressFW"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
             scale_down_worker_nodes
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
             get_ovn_node_system_usage_info
                      
             sleep 300
             echo "Save old node name and ovn pod list to old-node-ovn-pods.lst"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
             oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst  
             echo    "#############   ocp-node-ovn-pods-old.lst  #############" 
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
             cat /tmp/ocp-node-ovn-pods-old.lst
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
             scale_out_worker_nodes
      
             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
             oc get nodes |grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
             echo "New worker node and ovn pods when scaling out worker node"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u 
             echo 
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u | tr -s "\n" "|"
             echo
      
             sleep 600              
             export TEST_STEP="Restart OVN NODE POD With Large Scale PODs without BANP/ANP/"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             restartOVNPODs
       fi
       sleep 1800
       ###################################Create Default BANP#################################
       export TEST_STEP="Creating 1 BANP to setup zero trust deny egress/ingress policy."
       export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
       echo "Create BANP to deny traffic to host network/cidr cluster network and egress/ingress to specifiec ns"

       if [[ $IF_MASTER_CARD_CASE == "false" ]];then       
           oc apply -f ${WORKLOAD_TEMPLATE_PATH}/00_banp_deny-traffic-restricted.yaml
           printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/00_banp_deny-traffic-restricted.yaml
       else
           oc apply -f ${WORKLOAD_TEMPLATE_PATH}/00_banp_deny-traffic-mastercard.yaml
           printYAMLFile ${WORKLOAD_TEMPLATE_PATH}/00_banp_deny-traffic-mastercard.yaml  
       fi           
        export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
        get_ovn_node_system_usage_info
 
       ###################################Create Master Card Policy################################# 
       if [[ $IF_MASTER_CARD_CASE == "false" ]];then
       create_anp_banp_master_cards_verify_traffic_tween_different_zones
       fi
       ###################################Create CIDR Selector Policy#################################   
       if [[ $IF_MASTER_CARD_CASE == "true" ]];then        
       create_anp_banp_cidr_verify_traffic_tween_different_zones
       fi
       ###################################Create Node Selector Policy#################################
       if [[ $IF_MASTER_CARD_CASE == "false" ]];then    
            create_anp_banp_egress_rule_verify_traffic_from_two_different_groups_to_host
       fi
 
       ###################################Create POD Selector Policy################################# 
       if [[ $IF_MASTER_CARD_CASE == "false" ]];then  
            echo "Creating 14 POD Selector ANP to deny egress/ingress policy[Min]." 
            export TEST_STEP="Creating 14 POD Selector ANP to deny egress/ingress policy[Min]."
            export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
            create_anp_banp_verify_traffic_between_different_zones
            export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
            get_ovn_node_system_usage_info  
       fi

       export TEST_STEP="Creating ANP to Allow Egress to Kube API"
       export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
       create_anp_allow_egress_api "anp-test anp-restricted"
       export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
       get_ovn_node_system_usage_info

       export TEST_STEP="Creating ANP to Allow Monitor ANP "
       export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
       oc apply -f ${WORKLOAD_TEMPLATE_PATH}/01_anp_allow-common-service.yml
       export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
       get_ovn_node_system_usage_info

       #################################Recycle With Large Scale Pods And BANP/ANP#########################       
       if [[ $IF_RECYCLE_NODE == "true" ]];then
             #sleep 1800
             export TEST_STEP="Scaling Down Worker Nodes With Large Scale PODs with BANP/ANP"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
             scale_down_worker_nodes
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
             get_ovn_node_system_usage_info

             sleep 300
             echo "Save old node name and ovn pod list to old-node-ovn-pods.lst"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'       
             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
             oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst  
             echo    "#############   ocp-node-ovn-pods-old.lst  #############" 
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
             cat /tmp/ocp-node-ovn-pods-old.lst
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
             export TEST_STEP="Scale out worker nodes"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`              
             scale_out_worker_nodes
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`     
             get_ovn_node_system_usage_info   

             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
             oc get nodes |grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
             echo "New worker node and ovn pods when scaling out worker node"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u 
             echo 
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u | tr -s "\n" "|"
             echo
      
             sleep 600
             export TEST_STEP="Restart OVN Node POD with  Large Scale PODs and BANP/ANP"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             restartOVNPODs
       fi

       if [[ $IF_MASTER_CARD_CASE == "true" ]];then
            #sleep 600
            create_and_delete_anp_network_policy
            #sleep 600
            TOTAL_NODE=`oc get nodes -lnode-role.kubernetes.io/worker -oname|wc -l`
            EXPECT_RPLICAS=$(( $TOTAL_NODE * $POD_RPLICAS ))
            ANP_NAMESPACE=`oc get ns |grep anp-test |awk '{print $1}'| head -1`
            export TEST_STEP="Scale pods up to $EXPECT_RPLICAS"
            export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
            scale_pods_replicas_with_anp $ANP_NAMESPACE $EXPECT_RPLICAS
            export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
            get_ovn_node_system_usage_info

            #sleep 600
            export TEST_STEP="Scale pods down to 1"
            export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
            scale_pods_replicas_with_anp $ANP_NAMESPACE 1
            export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
            get_ovn_node_system_usage_info    

       fi
       sleep 1200 
       if [[ $IF_MASTER_CARD_CASE == "true" ]];then        
             #sleep 1800
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
             echo "Enable Logging for OVN Node Pods ...."
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
             
             create_configmap_to_override_logging_level

       fi
       cat /tmp/system_resource_info.csv
       sleep 1800

       #################################Creating Large Scale NetPol and Egress FW#########################  
       if [[ $IF_MASTER_CARD_CASE == "true" ]];then
             #sleep 1200
             export TEST_STEP="Creating Large Scale NetPol and Egress Firewall[Min]"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             echo "Creating networkpolicy enable pod traffic within the same namespace"
             for anptype in anp-cidr-np anp-open-np
             do
               WORKLOAD_TEMPLATE=workloads/large-networkpolicy-egress/case-large-networkpolicy-egress-${anptype}.yml
               run_workload
             done
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             get_ovn_node_system_usage_info
        fi

        if [[ $IF_MASTER_CARD_CASE == "false" ]];then         
             sleep 1200
             export TEST_STEP="Creating Large Scale NetPol and Egress Firewall[Min]"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             echo "Creating networkpolicy enable pod traffic within the same namespace"
             for anptype in anp-restricted-np anp-cidr-np anp-open-np anp-unknown-np 
             do
               WORKLOAD_TEMPLATE=workloads/large-networkpolicy-egress/case-large-networkpolicy-egress-${anptype}.yml
               run_workload
             done
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             get_ovn_node_system_usage_info            
        fi

       #################################Recycle With Large Scale Pods And BANP/ANP/NetPol/EFW#########################               
        if [[ $IF_RECYCLE_NODE == "true" ]];then        
             sleep 1800
             export TEST_STEP="Scaling Down Worker Nodes With Large Scale PODs and BANP/ANP/NetPol/EgressFW"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
             scale_down_worker_nodes
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
             get_ovn_node_system_usage_info

             sleep 600
             echo "Save old node name and ovn pod list to old-node-ovn-pods.lst"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'     
             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME | awk '{print $1}'>/tmp/ocp-node-ovn-pods-old.lst
             oc get nodes|grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-old.lst  
             echo    "#############   ocp-node-ovn-pods-old.lst  #############" 
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
             cat /tmp/ocp-node-ovn-pods-old.lst
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

             export TEST_STEP="Scaling Out Worker Nodes With Large Scale PODs and BANP/ANP/NetPol/EgressFW"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                
             scale_out_worker_nodes
             export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
             get_ovn_node_system_usage_info

             oc -n openshift-ovn-kubernetes get pods |grep -v -i NAME| awk '{print $1}'>/tmp/ocp-node-ovn-pods-new.lst
             oc get nodes |grep -v -i NAME | awk '{print $1}'>>/tmp/ocp-node-ovn-pods-new.lst
             echo "New worker node and ovn pods when scaling out worker node"
             awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u 
             echo 
             cat /tmp/ocp-node-ovn-pods-*.lst | sort -r| uniq -u | tr -s "\n" "|"
             echo
      
             sleep 600
             export TEST_STEP="Restart OVN Node POD with  Large Scale PODs and BANP/ANP"
             export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
             restartOVNPODs
        fi

        if [[ $IF_MASTER_CARD_CASE == "false" ]];then
            networkPolicyInitSyncDurationCheck
        fi

      #  export NODES_COUNT=`oc get nodes | grep worker |wc -l`
      #  export NAMESPACES=`oc get ns |grep anp| grep -v anp-node-http |wc -l`
      #  export PODS_PER_NAMESPACE=`oc get ns |grep anp-restricted | awk '{print $1}' | head -1 | xargs oc get pods -n |wc -l`
      #  export NETPOLS_PER_NAMESPACE=`oc get ns |grep anp-restricted | awk '{print $1}' | head -1 | xargs oc get networkpolicy -n |wc -l`
      #  WORKLOAD_TEMPLATE=workloads/large-networkpolicy-egress/case-large-networkpolicy-egress-anp-convergence-tracker.yml
      #  run_workload
 
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        cat /tmp/system_resource_info.csv
        
        sleep 1800
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo "Reboot worker nodes...."
        export TEST_STEP="Gracefully rotate worker node"
        export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`               
        for workerNode in `oc get nodes |grep worker | awk '{print $1}'|head -15`
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
        export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
        get_ovn_node_system_usage_info

        sleep 1800
        echo "Reboot single control plane node"
        FIRST_MASTER=`oc get nodes -lnode-role.kubernetes.io/master -oname|head -1`
        export TEST_STEP="Gracefully rotate a single control plane node"
        export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`       
        oc -n openshift-ovn-kubernetes debug $FIRST_MASTER -q -- chroot /host reboot&
        sleep 120
        for((i=0;i<=600;i++))
        do
           WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name master`
           if [[ $WORKER_MCP_STATUS == "true" ]];then
               echo The master mcp is ready
                   break
            fi
               echo -n "."&&sleep 10;
        done        
        export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
        get_ovn_node_system_usage_info
        echo "start to wait for 7200s"
        sleep 7200
        echo "end to wait for 7200s"        
        echo "Clean resource by ns"
        oc get ns | grep -E 'anp|zero'| awk '{print $1}' | xargs oc delete ns
        echo return code is $?
        cat /tmp/system_resource_info.csv
}