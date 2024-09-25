#!/usr/bin/env bash
set -m
# set -x
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

function verify_if_mcp_be_in_updated_state_by_name() {
	
    MCP_NAME=$1
    oc get mcp |grep $MCP_NAME
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

function enable_kube_burner_index(){
    export START_TIME=${START_TIME:=""}
    export END_TIME=${END_TIME:-""}
    export ES_INDEX="${ES_INDEX:-perfscale-qe-sdn2ovn}"
    export LOG_LEVEL=debug
    METRICS_PROFILE=metrics-profiles/metrics.yml
    if [[ -d /tmp/$UUID ]];then
        rm -rf /tmp/$UUID
    fi
    echo "INFO: Indexing the cluster results"
    pushd "${TEMP_DIR}"
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    OLD_PATH=`pwd`
    echo OLD_PATH is $OLD_PATH
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    if [ -d e2e-benchmarking/ ];then
       rm -rf e2e-benchmarking/  
    fi      
    git clone -b live-migration https://github.com/liqcui/e2e-benchmarking
    cd e2e-benchmarking/workloads/kube-burner-ocp-wrapper

    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'    
    NEW_PATH=`pwd`
    echo NEW_PATH is $NEW_PATH
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'    
    START_TIME=`date --date="20 min ago" +"%s"`
    END_TIME=`date +"%s"`
    START_TIME=${START_TIME} END_TIME=${END_TIME} WORKLOAD=index ./run.sh
    echo $START_TIME $END_TIME
    #ES_INDEX=ripsaw-kube-burner ES_SERVER=$ES_SERVER EXTRA_FLAGS="" KUBECONFIG=~/.kube/config WORKLOAD=index ./run.sh

    cd $OLD_PATH
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'    
    CUR_PATH=`pwd`
    echo CUR_PATH is $CUR_PATH
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}' 
    if [[ -d /tmp/$UUID ]];then
        rm -rf /tmp/$UUID
    fi
}



sdn2ovn_index_results(){
  export es_index="${ES_INDEX:-perfscale-qe-sdn2ovn}"
    METADATA=$(cat <<EOF
{
  "uuid": "${UUID}",
  "cluster_name": "$(oc get infrastructure.config.openshift.io cluster -o json 2>/dev/null | jq -r .status.infrastructureName)",
  "before_network_type": "$1",
  "after_network_type": "$2",
  "ovn_live_migration_duration": "$3",
  "ocp_version": "$4",
  "timestamp": "$(date +%s%3N)"
}
EOF
)
    printf "Indexing installation timings to ${ES_SERVER}/${_es_index}"
    curl -k -sS -X POST -H "Content-type: application/json" ${ES_SERVER}/${_es_index}/_doc -d "${METADATA}" -o /dev/null
    return 0
}

function live-migration-keepalive-detect(){
    LIVE_MIGRATION_DETECT_INTERVAL=${LIVE_MIGRATION_DETECT_INTERVAL:=1}
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
        oc -n ovn-live-migration-1 create route edge --service=keepalive-detect-nginx-cluster-ip-service
    fi
    echo "Start to OVN live migration ...."
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    #oc patch Network.config.openshift.io cluster --type='merge' --patch '{"metadata":{"annotations":{"unsupported-red-hat-internal-testing": "true"}}}'
    oc patch Network.config.openshift.io cluster --type='merge' --patch '{"metadata":{"annotations":{"network.openshift.io/network-type-migration":""}},"spec":{"networkType":"OVNKubernetes"}}'
    #4.15 oc patch Network.operator.openshift.io cluster --type='merge' --patch '{ "spec": { "migration": {"networkType": "OVNKubernetes" } } }'
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    export NW_MIGRATION_START=$(date +%s)
    echo "Start to delect if the service broken during OVN live migration ...."
    DETECT_ROUTE_NAME=`oc get route -A|grep keepalive-detect | awk '{print $3}'`
    while true;
    do
                curl -k -Is https://${DETECT_ROUTE_NAME}/ | head -n 3| grep OK;
                RC=$?;

                oc -n openshift-apiserver get pods | grep apiserver >/dev/null
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
                   echo "curl curl -k -Is https://${DETECT_ROUTE_NAME}/ output ....."
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
                NETWORK_TYPE=`oc get network.config.openshift.io cluster -o jsonpath='{.status.networkType}'`
    
                if [[ $NETWORK_TYPE == "OVNKubernetes" ]];then
                #if [[ $NETWORK_TYPE == "OpenShiftSDN" ]];then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       The OCP Network Type Changed to NETWORK_TYPE at `date +"%Y-%m-%d %H:%M:%S"`         #"
                   echo "#                     Current Network Type is $NETWORK_TYPE                    #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'     
                   break
                fi
                sleep $LIVE_MIGRATION_DETECT_INTERVAL;
                INIT=$(( $INIT + 1 ))
                if [[ $INIT -gt $MAX_RETRY ]];then
                   echo "max retry reached in live-migration-post-check"
                   exit 1
                fi
    done
}

function cluster_health_postcheck() {
 
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
  ! oc get co |sed '1d'|grep -v "openshift-samples"|grep -v ${target_version_prefix} || coVersionCheckResult=`oc get co |sed '1d'|grep -v "openshift-samples"|grep -v ${target_version_prefix}|awk '{print $1}'|while read line; do oc describe co $line;done`
  echo coVersionCheckResult is $coVersionCheckResult
  echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"


  if [ -z "$nodeStatusCheckResult" ] && [ -z "$coStatusCheckResult" ] && [ -z "$coVersionCheckResult" ]; then
      echo -e "post check passed without err.\n"
  else
      oc get nodes
      oc describe nodes
  fi

}

function migration_checkpoint(){
     echo "Network connection testing from pod to pod(same node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     echo "Checking Items, Result, Command,Output">/tmp/checkResult.csv
     POD_NAME=`oc -n ovn-live-migration-1 get pods -ltrafficapp=perfapp -oname |head -1`
     CMD="oc -n ovn-live-migration-1 logs $POD_NAME --tail=6 |grep 'Timestamp inserted in'"
     OUTPUT=`oc -n ovn-live-migration-1 logs $POD_NAME --tail=6 |grep 'Timestamp inserted in' |tail -1`
     oc -n ovn-live-migration-1 logs $POD_NAME --tail=6 |grep 'Timestamp inserted in'
     if [[ $? -eq 0 ]];then
        echo "Network connection testing from pod to pod(same node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to pod(same node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to pod(cross node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     POD_IP=`oc -n ovn-live-migration-1 get pod -lapp=workload-nginx-app -ojsonpath={.items[0].status.podIP}`
     CMD="oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $POD_IP 8080"
     OUTPUT=`oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $POD_IP 8080 |grep Connected`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $POD_IP 8080
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to pod(cross node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to pod(cross node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to host(same node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     HOST_IP=`oc -n ovn-live-migration-1 get $SOURCE_POD_NAME -ojsonpath={.status.hostIP}`
     CMD="oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250"
     OUTPUT=`oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250 |grep Connected`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to host(same node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to host(same node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to host(cross node)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     HOST_IP=`oc -n ovn-live-migration-1 get pod -lapp=workload-nginx-app -ojsonpath={.items[0].status.hostIP}`
     CMD="oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250"
     OUTPUT=`oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250 |grep Connected`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 10250
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod to host(cross node),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
        echo "Network connection testing from pod to host(cross node),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo 
     echo "Network connection testing from pod to ClusterIP service"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     CMD="oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz keepalive-detect-nginx-cluster-ip-service 8080"
     OUTPUT=`oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz keepalive-detect-nginx-cluster-ip-service 8080 |grep Connected`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz keepalive-detect-nginx-cluster-ip-service 8080
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
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pods -lapp=workload-tool -oname`
     HOST_IP=`oc get nodes -l"${NODE_LABEL}" -ojsonpath='{range .items[0]}{.status.addresses[?(@.type=="InternalIP")].address}'`
     CMD="oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036"
     OUTPUT=`oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036 |grep Connected`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036
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
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     HOST_IP=`oc get nodes -l"${NODE_LABEL}" -ojsonpath='{range .items[0]}{.status.addresses[?(@.type=="InternalIP")].address}'`
     CMD="oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036"
     OUTPUT=`oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036 |grep Connected`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036
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
     CMD="oc -n ovn-live-migration-1 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 30036"
     OUTPUT=`oc -n ovn-live-migration-1 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 30036 |grep Connected`
     oc -n ovn-live-migration-1 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 30036
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
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     CMD="oc -n ovn-live-migration-1 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'"
     OUTPUT=`oc -n ovn-live-migration-1 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'| head -1`
     oc -n ovn-live-migration-1 exec -it $SOURCE_POD_NAME -- nc -vz $HOST_IP 30036
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
     #oc -n ovn-live-migration-1 get services keepalive-detect-nginx-loadbalancer-service -ojsonpath='{.status.loadBalancer.ingress[0].hostname}'
     HOST_IP=`oc -n ovn-live-migration-1 get services | grep keepalive-detect-nginx-loadbalancer-service | awk '{print $4}'`
     SOURCE_POD_NAME=`oc -n ovn-live-migration-1 get pod -lapp=external-traffic -oname`
     CMD="oc -n ovn-live-migration-1 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 8080 | grep Connected"
     OUTPUT=`oc -n ovn-live-migration-1 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 8080 |grep Connected`
     oc -n ovn-live-migration-1 debug node/${MASTER_NODE} -q -- chroot /host nc -vz $HOST_IP 8080 |grep Connected
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
     SOURCE_POD_NAME=`oc -n anp-restricted-1  get pods -ltrafficapp=perfata -oname | head -1`
     CMD="oc -n anp-restricted-1 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'"
     OUTPUT=`oc -n anp-restricted-1 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200' | head -1`
     oc -n anp-restricted-1 logs $SOURCE_POD_NAME --tail=20|grep 'HTTP/.* 200'
     if [[ $? -eq 0 ]];then
	     echo "Network connection testing from pod with netpol(cross ns),Passed,$CMD,$OUTPUT">>/tmp/checkResult.csv
     else
	     echo "Network connection testing from pod with netpol(cross ns),Failure,$CMD,$OUTPUT" >>/tmp/checkResult.csv
     fi
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

     echo
     echo "Network connection testing from pod to pod with netpol(same ns)"
     awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
     SOURCE_POD_NAME=`oc -n anp-restricted-1  get pods -ltrafficapp=perfapp -oname | head -1`
     CMD="oc -n anp-restricted-1 logs $SOURCE_POD_NAME --tail=20|grep 'Timestamp inserted'"
     OUTPUT=`oc -n anp-restricted-1 logs $SOURCE_POD_NAME --tail=20|grep 'Timestamp inserted' | head -1`
     oc -n anp-restricted-1 logs $SOURCE_POD_NAME --tail=20|grep 'Timestamp inserted'
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

}

function live-migration-post-check(){
    INIT=1
    MAX_RETRY=${MAX_RETRY:=7200}
    echo The max retry is $MAX_RETRY
    echo "Start to delect if the service broken during the second reboot of OVN live migration ...."
    
    DETECT_ROUTE_NAME=`oc get route -A|grep keepalive-detect | awk '{print $3}'`
    while true;
    do
                curl -k -Is https://${DETECT_ROUTE_NAME}/ | head -n 3 | grep OK;
                RC=$?;
                if [ $RC -ne 0 ] ; then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#       [Failure] Service broken during ovn live migration at `date +"%Y-%m-%d %H:%M:%S"`      #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                fi;
               
                MASTER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name master`
                WORKER_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name worker`
                INFRA_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name infra`
                WORKLOAD_MCP_STATUS=`verify_if_mcp_be_in_updated_state_by_name workload`
    
                if [[ $MASTER_MCP_STATUS == "true" && $WORKER_MCP_STATUS == "true" && $INFRA_MCP_STATUS == "true" && $WORKLOAD_MCP_STATUS == "true" ]];then
                #if [[ $NETWORK_TYPE == "OpenShiftSDN" ]];then
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                   echo "#            OVN Live Migration Successfully at `date +"%Y-%m-%d %H:%M:%S"`            #"
                   echo "#                     Current Network Type is $NETWORK_TYPE                    #"
                   awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'     
                   break
                fi
                sleep 5;
                INIT=$(( $INIT + 1 ))
                if [[ $INIT -gt $MAX_RETRY ]];then
                   echo "max retry reached in live-migration-post-check"
                   exit 1
                fi
    done
    sleep 600
    cluster_health_postcheck
    export NW_MIGRATION_STOP=$(date +%s)
    sleep 600
    migration_checkpoint
    echo "Finished CNI migration"
    
    # NW_MIGRATION_DURATION=$((NW_MIGRATION_STOP - NW_MIGRATION_START - 300))
    # export AFTER_N_TYPE=$(oc get Network.operator.openshift.io cluster  -o json | jq -r '.spec.defaultNetwork.type')
    # sdn2ovn_index_results "$BEFORE_N_TYPE" "$AFTER_N_TYPE" "$NW_MIGRATION_DURATION" "$OPENSHIFT_VERSION"
}
