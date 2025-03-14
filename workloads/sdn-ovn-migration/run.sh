#!/usr/bin/bash
set -e
. common.sh
. build_helper.sh
. ../../utils/compare.sh
source ./egressip.sh

ES_SERVER=${ES_SERVER=https://search-perfscale-dev-chmf5l4sh66lvxbnadi4bznl3a.us-west-2.es.amazonaws.com}
LOG_LEVEL=${LOG_LEVEL:-info}
if [ "$KUBE_BURNER_VERSION" = "default" ]; then
    unset KUBE_BURNER_VERSION
fi
KUBE_BURNER_VERSION=${KUBE_BURNER_VERSION:-1.3.2}
CHURN=${CHURN:-true}
WORKLOAD=${WORKLOAD:?}
QPS=${QPS:-20}
BURST=${BURST:-20}
GC=${GC:-true}
EXTRA_FLAGS=${EXTRA_FLAGS:-}
UUID=${UUID:-$(uuidgen)}
KUBE_DIR=${KUBE_DIR:-/tmp}
#KUBE_DIR=./customized-workload

#Mixed Workload Scenaio
export ES_INDEX=${ES_INDEX:="ovn-live-migration"}
export POD_RPLICAS=${POD_RPLICAS:=3}
export NETWORKPOLICY_RPLICAS=${NETWORKPOLICY_RPLICAS:=3}
export POD_NODE_SELECTOR=${POD_NODE_SELECTOR:-'{node-role.kubernetes.io/worker: }'}
export WORKER_NODE_LABEL=${WORKER_NODE_LABEL:-"node-role.kubernetes.io/worker"}
export WORKLOAD_POD_NODE_SELECTOR=${WORKLOAD_POD_NODE_SELECTOR:-'{node-role.kubernetes.io/workload: }'}
export BACKEND_POD_NODE_SELECTOR=${BACKEND_POD_NODE_SELECTOR:-'{node-role.kubernetes.io/backend: }'}
export SDN_OVN_RESTRICTED_ITERATION=${SDN_OVN_RESTRICTED_ITERATION:="1"}
export SDN_OVN_LIVE_MIGRATION_ITERATION=${SDN_OVN_LIVE_MIGRATION_ITERATION:="1"}
export ENABLE_INGRESS_CONTROLLER=${ENABLE_INGRESS_CONTROLLER:="true"}
export IF_CUSTOMIZED_KUBE_BURNER_WORKLOAD=${IF_CUSTOMIZED_KUBE_BURNER_WORKLOAD:="false"}
export MAX_UNAVAILABLE=${MAX_UNAVAILABLE:=1}
export IF_SLEEP_WAIT_IN_EACH_PHASE=${IF_SLEEP_WAIT_IN_EACH_PHASE:="false"}
export KUBE_BURNER_POD_REPLICAS=${KUBE_BURNER_POD_REPLICAS:="1"}
# Pprof #Required
export PPROF_COLLECTION=${PPROF_COLLECTION:-false}
export PPROF_COLLECTION_INTERVAL=${PPROF_COLLECTION_INTERVAL:-5m}
export IF_SCLAE_OUT_NODES=${IF_SCLAE_OUT_NODES:="false"}
export ONLY_POST_CHECKING=${ONLY_POST_CHECKING:="false"}
export EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM=52
export ENABLE_EGRESS_POLICY=${ENABLE_EGRESS_POLICY:="false"}
download_binary(){
  KUBE_BURNER_URL="https://github.com/kube-burner/kube-burner-ocp/releases/download/v${KUBE_BURNER_VERSION}/kube-burner-ocp-V${KUBE_BURNER_VERSION}-linux-x86_64.tar.gz"
  curl --fail --retry 8 --retry-all-errors -sS -L "${KUBE_BURNER_URL}" | tar -xzC "${KUBE_DIR}/" kube-burner-ocp
  ls ${KUBE_DIR}/
}

hypershift(){
  echo "HyperShift detected"

  # Get hosted cluster ID and name
  HC_ID=$(oc get infrastructure cluster -o go-template --template='{{.status.infrastructureName}}')
  HC_PLATFORM=$(oc get infrastructure cluster -o go-template --template='{{.status.platform}}'| awk '{print tolower($0)}')

  if [[ $HC_PLATFORM == "aws" ]]; then
    echo "Detected ${HC_PLATFORM} environment..."

    MC_NAME=$(oc get --kubeconfig=${MC_KUBECONFIG} infrastructure.config.openshift.io cluster -o json 2>/dev/null | jq -r .status.infrastructureName)
    HC_NAME=$(oc get infrastructure cluster -o go-template --template='{{range .status.platformStatus.aws.resourceTags}}{{if eq .key "api.openshift.com/name" }}{{.value}}{{end}}{{end}}')
    # Hosted control-plane namespace is composed by the cluster ID plus the cluster name
    HCP_NAMESPACE=${HC_ID}-${HC_NAME}
    QUERY="sum(cluster:nodes_roles{label_hypershift_openshift_io_control_plane=\"true\"})by(node)"

    echo "Creating OBO route on MC"
    oc --kubeconfig=${MC_KUBECONFIG} apply -f obo-route.yml
    echo "Fetching OBO endpoint"
    MC_OBO=http://$(oc --kubeconfig=${MC_KUBECONFIG} get route -n openshift-observability-operator prometheus-hypershift -o jsonpath="{.spec.host}")
    MC_PROMETHEUS=https://$(oc --kubeconfig=${MC_KUBECONFIG} get route -n openshift-monitoring prometheus-k8s -o jsonpath="{.spec.host}")
    MC_PROMETHEUS_TOKEN=$(oc --kubeconfig=${MC_KUBECONFIG} sa new-token -n openshift-monitoring prometheus-k8s)
    HC_PRODUCT="rosa"
  else
    echo "Detected ${HC_PLATFORM} environment..."

    MC_NAME=$(kubectl config view -o jsonpath='{.clusters[].name}' --kubeconfig=${MC_KUBECONFIG})
    HC_NAME=$(oc get infrastructure cluster -o go-template --template='{{.status.etcdDiscoveryDomain}}' | awk -F. '{print$1}')
    HCP_NAMESPACE=${HC_NAME}
    QUERY="sum(kube_node_role{cluster=\"$MC_NAME\",role=\"worker\"})by(node)"

    if [[ -z ${AKS_PROM} ]] || [[ -z ${AZURE_PROM} ]] ; then
      echo "Azure/AKS prometheus inputs are missing, exiting.."
      exit 1
    elif [[ -z ${AZURE_PROM_TOKEN} ]]; then
      if [[ -z ${AZ_CLIENT_SECRET} ]] || [[ -z ${AZ_CLIENT_ID} ]] ; then
        echo "Azure/AKS prometheus token is missing and cannot be calculated, exiting.."
	exit 1
      else
	AZURE_PROM_TOKEN=$(curl --request POST 'https://login.microsoftonline.com/64dc69e4-d083-49fc-9569-ebece1dd1408/oauth2/v2.0/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "client_id=${AZ_CLIENT_ID}" --data-urlencode 'grant_type=client_credentials' --data-urlencode "client_secret=${AZ_CLIENT_SECRET}" --data-urlencode 'scope=https://prometheus.monitor.azure.com/.default' | jq -r '.access_token')
      fi
    fi

    MC_OBO=$AKS_PROM
    MC_PROMETHEUS=$AZURE_PROM
    MC_PROMETHEUS_TOKEN=$AZURE_PROM_TOKEN
    HC_PRODUCT="aro"
  fi

  echo "Indexing Management cluster stats"
  METADATA=$(cat << EOF
{
"uuid": "${UUID}",
"workload": "${WORKLOAD}",
"mgmtClusterName": "${MC_NAME}",
"hostedClusterName": "${HC_NAME}",
"timestamp": "$(date +%s%3N)"
}
EOF
)
  curl -k -sS -X POST -H "Content-type: application/json" ${ES_SERVER}/${ES_INDEX}/_doc -d "${METADATA}" -o /dev/null

  HOSTED_PROMETHEUS=https://$(oc get route -n openshift-monitoring prometheus-k8s -o jsonpath="{.spec.host}")
  HOSTED_PROMETHEUS_TOKEN=$(oc sa new-token -n openshift-monitoring prometheus-k8s)

  echo "Get all management worker nodes, excludes infra, obo, workload"
  Q_NODES=""
  Q_STDOUT=$(curl -H "Authorization: Bearer ${MC_PROMETHEUS_TOKEN}" -k --silent --globoff  ${MC_PROMETHEUS}/api/v1/query?query=${QUERY}&time='$(date +"%s")')
  for n in $(echo $Q_STDOUT | jq -r '.data.result[].metric.node'); do
    if [[ ${Q_NODES} == "" ]]; then
      Q_NODES=${n}
    else
      Q_NODES=${Q_NODES}"|"${n};
    fi
  done
  MGMT_WORKER_NODES=${Q_NODES}

  echo "Exporting required vars"
  cat << EOF
MC_NAME: ${MC_NAME}
MC_OBO: ${MC_OBO}
MC_PROMETHEUS: ${MC_PROMETHEUS}
MC_PROMETHEUS_TOKEN: <truncated>
HOSTED_PROMETHEUS: ${HOSTED_PROMETHEUS}
HOSTED_PROMETHEUS_TOKEN: <truncated>
HCP_NAMESPACE: ${HCP_NAMESPACE}
MGMT_WORKER_NODES: ${MGMT_WORKER_NODES}
HC_PRODUCT: ${HC_PRODUCT}
EOF

  if [[ ${WORKLOAD} =~ "index" ]]; then
    export elapsed=${ELAPSED:-20m}
  fi
  
  export MC_OBO MC_PROMETHEUS MC_PROMETHEUS_TOKEN HOSTED_PROMETHEUS HOSTED_PROMETHEUS_TOKEN HCP_NAMESPACE MGMT_WORKER_NODES HC_PRODUCT MC_NAME

}

download_binary

if [[ ${WORKLOAD} =~ "index" ]]; then
  cmd="${KUBE_DIR}/kube-burner-ocp index --uuid=${UUID} --start=$START_TIME --end=$((END_TIME + 600)) --metrics-profile=$METRICS_PROFILE --log-level ${LOG_LEVEL}"
  JOB_START=$(date -u -d "@$START_TIME" +"%Y-%m-%dT%H:%M:%SZ")
  JOB_END=$(date -u -d "@$((END_TIME + 600))" +"%Y-%m-%dT%H:%M:%SZ")
else
  cmd="${KUBE_DIR}/kube-burner-ocp ${WORKLOAD} --log-level=${LOG_LEVEL} --qps=${QPS} --burst=${BURST} --gc=${GC} --uuid ${UUID}"
fi
cmd+=" ${EXTRA_FLAGS}"
if [[ ${WORKLOAD} =~ "cluster-density" ]] && [[ ! ${WORKLOAD} =~ "web-burner" ]] ; then
  ITERATIONS=${ITERATIONS:?}
  cmd+=" --iterations=${ITERATIONS} --churn=${CHURN}"
fi
if [[ ${WORKLOAD} =~ "egressip" ]]; then
  prep_aws
  get_egressip_external_server
  ITERATIONS=${ITERATIONS:?}
  cmd+=" --iterations=${ITERATIONS} --external-server-ip=${EGRESSIP_EXTERNAL_SERVER_IP}"
fi
if [[ -n ${MC_KUBECONFIG} ]] && [[ -n ${ES_SERVER} ]]; then
  cmd+=" --metrics-endpoint=metrics-endpoint.yml"
  hypershift
fi
# If ES_SERVER is specified
if [[ -n ${ES_SERVER} ]]; then
  cmd+=" --es-server=${ES_SERVER} --es-index=${ES_INDEX}"
fi

echo "###############################################"
if [[ ${PPROF_COLLECTION} == "true" ]] ; then
  delete_pprof_secrets
  delete_oldpprof_folder
  get_pprof_secrets
fi

if [[ ${WORKLOAD} =~ "egressip" ]]; then
    cleanup_egressip_external_server
fi

# Capture the exit code of the run, but don't exit the script if it fails.
set +e

echo $cmd

#Limited SDN to OVN live migration and Mixed Scenario of Large Scale Pods/NetPol/EgressFirewall
echo -e "Test Step,Create Time, Query Time, Max Master CPU,Max Master RAM,Max Worker CPU,Max Worker RAM,ACL,Match ACL,Port Group,Address Set,lflow-list, DumpFlows" > /tmp/system_resource_info.csv

#Excute standard and customized kube-burner workload
if [[ $WORKLOAD == "cluster-density-v2" ]];then

     if [[ ${IF_SLEEP_WAIT_IN_EACH_PHASE} == "true" ]];then
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'   
          echo "Sleep 15 minutes before executing the kube-burner-ocp ..."
          awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
          sleep 900
     fi

JOB_START=${JOB_START:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}
cat << EOF
###############################################
Workload: $WORKLOAD
QPS: ${QPS}
Burst: ${BURST}
UUID: ${UUID}
JOB_START: ${JOB_START}
###############################################
EOF
        
              if [[ $IF_CUSTOMIZED_KUBE_BURNER_WORKLOAD == "true" ]];then
                  cd customized-workload
                  EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=./egress-firewall-policy.yml
                  generated_egress_firewall_policy $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM
                  cat ./egress-firewall-policy.yml
                  
                  ${KUBE_DIR}/kube-burner-ocp cluster-density-v2 --extract                 
                  sed -i "s/podReplicas: 2/podReplicas: ${KUBE_BURNER_POD_REPLICAS}/" cluster-density-v2.yml
                  sed -i 's/replicas: 3/replicas: 11/' cluster-density-v2.yml
                  sed -i 's/replicas: 2/replicas: 3/' cluster-density-v2.yml
                  sed -i 's/replicas: 11/replicas: 2/' cluster-density-v2.yml
                  #service number
                  sed -i 's/replicas: 5/replicas: 3/' cluster-density-v2.yml
                  sed -i 's/replicas: 10/replicas: 5/' cluster-density-v2.yml
                  #service number
                  sed -i 's/randInt 1 6/randInt 1 2/'  deployment-client.yml                
                  # #Remove Network Policy
                  # sed -i '/np-deny-all.yml/, +9d' cluster-density-v2.yml
                  # sed -i '/np-deny-all.yml/{N;N;d;}' cluster-density-v2.yml
                  # sed -i '/np-allow-from-clients.yml/{N;N;d;}' cluster-density-v2.yml
                  # sed -i '/np-allow-from-ingress.yml/{N;d;}' cluster-density-v2.yml

                  # sed -i 's/replicas: 3/replicas: 11/' cluster-density-v2.yml
                  # sed -i 's/replicas: 5/replicas: 18/' cluster-density-v2.yml
                  # sed -i 's/replicas: 2/replicas: 3/' cluster-density-v2.yml
                  # sed -i 's/replicas: 11/replicas: 2/' cluster-density-v2.yml
                  echo -e "\n      - objectTemplate: egress-firewall-policy.yml\n        replicas: 1">>cluster-density-v2.yml 
                  echo "---------------------------------------------------"
                  cat    cluster-density-v2.yml
                  echo "---------------------------------------------------"  
                  cd ..                   
              fi
              $cmd
              JOB_END=${JOB_END:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")};
              env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh
              echo
      fi


#Execute limited sdn to ovn live migration
if [[ ${WORKLOAD} == "sdn-ovn-migration" ]];then
#if [[ ${OVN_LIVE_MIGRATION} == "true" && ${WORKLOAD} == "sdn-ovn-migration" ]];then
     if [[ $ONLY_POST_CHECKING == "false" ]];then
          echo oc patch machineconfigpool/worker --type=\'merge\' -p=\'\{\"spec\":\{\"maxUnavailable\": $MAX_UNAVAILABLE }}\' | envsubst| bash
          JOB_START=${JOB_START:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")};
cat << EOF
###############################################
Workload: ${WORKLOAD}
QPS: ${QPS}
Burst: ${BURST}
UUID: ${UUID}
JOB_START: ${JOB_START}
###############################################
EOF
                #Used for prow ci job, we need to execute cluster-density-v2 job first before upgrade
                if [[ ${ENABLE_EGRESS_POLICY} == "true" ]];then

                    cd customized-workload
                    EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=./egress-firewall-policy.yml
                    generated_egress_firewall_policy $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM
                    cat ./egress-firewall-policy.yml
                    echo ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID}  --iterations=${ITERATIONS} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} -c customized-workload-template.yml
                    ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --iterations=${ITERATIONS} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} -c customized-workload-template.yml
                  
                    cd ..
                fi

                #Create Customized Ingress Controller 
                if [[ ${ENABLE_INGRESS_CONTROLLER} == "true" ]]; then             
                      create_ingress_controller               
                fi    
                JOB_END=${JOB_END:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")};
                env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh
                echo

                cd customized-workload
                LABEL_NODE=`oc get nodes |grep worker | awk '{print $1}' | head -1`
                oc label node $LABEL_NODE node-role.kubernetes.io/backend=
                echo -e "\nCreating pods in sdn-ovn-restricted-x"
                awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

                
                if [[ $NETWORKPOLICY_RPLICAS -lt $POD_RPLICAS ]];then
                      unset NETWORKPOLICY_RPLICAS
                      export NETWORKPOLICY_RPLICAS=$POD_RPLICAS
                fi

                echo  ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} -c case-sdn-ovn-networkpolicy-egress-restricted.yml
                ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} -c case-sdn-ovn-networkpolicy-egress-restricted.yml
                awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                echo -e "\nCreating pods in sdn-ovn-migration-x"
                awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                echo ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} -c case-limited-sdn-to-ovnk-live-migration.yml
                ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} -c case-limited-sdn-to-ovnk-live-migration.yml
                cd ..

                JOB_END=${JOB_END:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")};
                env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh  
                echo

                if [[ ${EnableAutoScaler} == "true" ]];then
                echo "Creating autoscaler ...."
                echo "---------------------------------------------------"
                createAutoscaler
                fi
                 
                if [[ ${IF_SLEEP_WAIT_IN_EACH_PHASE} == "true" ]];then
                 echo "Sleep 15 minutes after executing the kube-burner-ocp and creating all resources..."  
                 sleep 900
                 export TEST_STEP="15 minutes after creating large scale pod/netpol/egressfirewall"
                 export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`                   
                 export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
                 get_ovn_node_system_usage_info
                fi
            
                # sdn-ovn-live-migration-keepalive-detect-phaseI
                # sleep 180
                # sdn-ovn-live-migration-keepalive-detect-phaseII
            
                if [[ ${EnableIndex} == "true" ]];then
                   echo "waiting for 300s, then save kubeburner index"
                   sleep 300
                   enable_kube_burner_index
                fi            

                awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                echo -e "\nWating for 15 minutes to check cluster health"
                sleep 900
                cluster_health_basic_check
      
                awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                echo -e "\nWating for 15 minutes to check if all resource work as expect"
                sleep 900         
                sdn_ovn_live_migration_checkpoint
                echo "Finished CNI migration"
                awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
                cat /tmp/system_resource_info.csv
                awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
    

                awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'          
                echo "waiting for 300s, then test scale out/scale down worker node after migration"
                sleep 300
                export TEST_STEP="Scale out/down after OVN CNI migration"
                export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
                if [[ $IF_SCLAE_OUT_NODES == "true" ]];then
                    scale_out_up_nodes
                    scale_out_down_nodes
                fi
                
                export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
                get_ovn_node_system_usage_info 
                
    
                if [[ ${IF_SLEEP_WAIT_IN_EACH_PHASE} == "true" ]];then
                 awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
                 echo -e "\nSleep 30 minutes after OVN CNI migration PhaseII"
                 awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'         
                 export TEST_STEP="Sleep 30 minutes after OVN CNI migration PhaseII"
                 export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
                 sleep 1800
                 export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
                 get_ovn_node_system_usage_info
                fi
                recycle_worker_node
           else 
                echo "Only post check for limited sdn to ovn live migration"
                sdn-ovn-live-migration-keepalive-detect-phaseII
                if [[ ${EnableIndex} == "true" ]];then
                    enable_kube_burner_index
                fi
           fi

           JOB_END=${JOB_END:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")};
           env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh
           echo                        
           echo "Limited SDN to OVN Live Migration Completed"
fi

exit_code=$?
if [ $exit_code -eq 0 ]; then 
  JOB_STATUS="success"
else
  JOB_STATUS="failure"
fi
echo The job is $JOB_STATUS