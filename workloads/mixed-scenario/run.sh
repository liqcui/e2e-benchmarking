#!/usr/bin/bash
set -e
. common.sh
. build_helper.sh
. ../../utils/compare.sh
source ./egressip.sh
#set -x

export ES_SERVER=${ES_SERVER=https://search-perfscale-dev-chmf5l4sh66lvxbnadi4bznl3a.us-west-2.es.amazonaws.com}
export ES_INDEX=${ES_INDEX:="large-scale-anp-netpol"}
LOG_LEVEL=${LOG_LEVEL:-info}
if [ "$KUBE_BURNER_VERSION" = "default" ]; then
    unset KUBE_BURNER_VERSION
fi
KUBE_BURNER_VERSION=${KUBE_BURNER_VERSION:-1.6.2}
#KUBE_BURNER_VERSION=${KUBE_BURNER_VERSION:-1.3.2}
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
export IF_MIXED_SCENARIO=${IF_MIXED_SCENARIO:="false"}
export POD_REPLICAS=${POD_REPLICAS:=1}
export NETWORKPOLICY_RPLICAS=${NETWORKPOLICY_RPLICAS:=3}
export POD_NODE_SELECTOR=${POD_NODE_SELECTOR:-'{node-role.kubernetes.io/worker: }'}
export WORKER_NODE_LABEL=${WORKER_NODE_LABEL:-"node-role.kubernetes.io/worker"}
export WORKLOAD_POD_NODE_SELECTOR=${WORKLOAD_POD_NODE_SELECTOR:-'{node-role.kubernetes.io/workload: }'}
export BACKEND_POD_NODE_SELECTOR=${BACKEND_POD_NODE_SELECTOR:-'{node-role.kubernetes.io/backend: }'}
#export ENABLE_INGRESS_CONTROLLER=${ENABLE_INGRESS_CONTROLLER:="false"}
export MAX_UNAVAILABLE=${MAX_UNAVAILABLE:=1}
export IF_SLEEP_WAIT_IN_EACH_PHASE=${IF_SLEEP_WAIT_IN_EACH_PHASE:="false"}
# Pprof #Required
export PPROF_COLLECTION=${PPROF_COLLECTION:-false}
export PPROF_COLLECTION_INTERVAL=${PPROF_COLLECTION_INTERVAL:-5m}
export ENABLE_EGRESS_FIREWALL_POLICY=${ENABLE_EGRESS_FIREWALL_POLICY:="false"}
export POD_SECLECTOR_ANP_NS_NUM=${POD_SECLECTOR_ANP_NS_NUM:="8"}
export CIDR_SECLECTOR_ANP_NS_NUM=${CIDR_SECLECTOR_ANP_NS_NUM:="8"}
export POD_READY_THRESHOLD=${POD_READY_THRESHOLD:-5000ms}
export ENABLE_NETWORK_POLICY=${ENABLE_NETWORK_POLICY:="false"}
export NO_VERIFY_ANP=${NO_VERIFY_ANP:="false"}
export IF_EANBLE_ANP_LOGGING=${IF_EANBLE_ANP_LOGGING:="false"}
export IF_SCALE_NODE_TESTING=${IF_SCALE_NODE_TESTING:="false"}
export IF_RECYCLE_NODE_TESTING=${IF_RECYCLE_NODE_TESTING:="false"}
export RESTART_OVN_PODS=${RESTART_OVN_PODS:="false"}
export METRICS_PROFILE=${METRICS_PROFILE:="metrics-profiles/metrics-report.yml"}
export IF_DEPLOY_CUSTOMIZED_DASHBOARD=${IF_DEPLOY_CUSTOMIZED_DASHBOARD:="true"}
export IF_ONLY_ANP=${IF_ONLY_ANP="false"}
export IF_ENABLE_SCALE_METRIC=${IF_ENABLE_SCALE_METRIC="true"}

download_binary(){
  KUBE_BURNER_URL="https://github.com/kube-burner/kube-burner-ocp/releases/download/v${KUBE_BURNER_VERSION}/kube-burner-ocp-V${KUBE_BURNER_VERSION}-linux-x86_64.tar.gz"
  curl --fail --retry 8 --retry-all-errors -sS -L "${KUBE_BURNER_URL}" | tar -xzC "${KUBE_DIR}/" kube-burner-ocp
  ls ${KUBE_DIR}/
}

download_binary

echo "###############################################"
if [[ ${PPROF_COLLECTION} == "true" ]] ; then
  delete_pprof_secrets
  delete_oldpprof_folder
  get_pprof_secrets
fi

# Capture the exit code of the run, but don't exit the script if it fails.
set +e


#Limited SDN to OVN live migration and Mixed Scenario of Large Scale Pods/NetPol/EgressFirewall
echo -e "Test Step,Create Time, Query Time, Max Master CPU,Max Master RAM,Max Worker CPU,Max Worker RAM,ACL,Match ACL,Port Group,Address Set,lflow-list, DumpFlows" > /tmp/system_resource_info.csv

#Excute customized kube-burner-ocp workload, will change the WORKLOAD to mixed-scenario later
if [[ $WORKLOAD == "mixed-scenario" ]];then
#if [[ $WORKLOAD == "cluster-density-v2" ]];then
        
        waiting_for_during_each_phase "Phase I" 900 "before creating large scale pods" false

        #Prepare Testing Environment
        if [[ $IF_ENABLE_SCALE_METRIC == "true" ]];then
            echo "Enable metrics-enable-scale for ovn-node-xxx pods in ns openshift-ovn-kubernetes"
            oc scale deployment cluster-version-operator -n openshift-cluster-version --replicas=0
            oc scale deployment network-operator -n openshift-network-operator --replicas=0
            oc -n openshift-ovn-kubernetes get configmap ovnkube-script-lib -oyaml>ovnkube-script-lib.yaml
            
            sed -i 's:--enable-interconnect:--enable-interconnect      --metrics-enable-scale:' ovnkube-script-lib.yaml
            sed -i 's:--enable-interconnect  :--enable-interconnect \\\\\\n:' ovnkube-script-lib.yaml
            oc -n openshift-ovn-kubernetes delete configmap ovnkube-script-lib
            oc -n openshift-ovn-kubernetes create -f ovnkube-script-lib.yaml
            sleep 30
            echo "Restart all ovn-node-xxx pod after change the  metrics-enable-scale"
            oc -n openshift-ovn-kubernetes get pods | grep ovnkube-node| awk '{print $1}'| xargs oc -n openshift-ovn-kubernetes delete pod
            oc -n openshift-ovn-kubernetes wait --timeout=120s --for=condition=Ready pod -l app=ovnkube-node
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

        echo "Creating customized workload"
        cd customized-workloads

        awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
        echo -e "Prepare Testing Environment for BANP/ANP/NetPol/EgressFirewall with Large Scale Pods\nTo simulate customer workload"
        awk 'BEGIN{for(c=0;c<80;c++) printf "#"; printf "\n"}'
        echo
        export TEST_STEP="Creating Large Scale Pods"
        export CREATE_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"`
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo "Creating perfscale workload as target services"
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        export CUSTOMIZED_WORKLOAD_FILE=./customized-workload.yml
        export CUSTOMIZED_ITERATIONS=1
        create_customized_workload perfscale-workload workload
        append_customized_workload4Pods perfscale-workload perfworkload-tool.yml
        append_customized_workload4Pods perfscale-workload ingress-route-request-app.yaml
        echo -e "          ingressDomain: {{.INGRESS_DOMAIN}}">>$CUSTOMIZED_WORKLOAD_FILE
        unset CUSTOMIZED_ITERATIONS

        cat $CUSTOMIZED_WORKLOAD_FILE
        echo  ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
        ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
        oc adm policy add-scc-to-user privileged -z default -n perfscale-workload-0
        oc -n perfscale-workload-0 apply -f perfnode-daemonset.yaml
        oc -n perfscale-workload-0 wait --timeout=120s --for=condition=Ready pod -l app=node-traffic-httpsvr
  
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo "Creating large scale workload for ANP/NetPol/EgressFirewall Testing"
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'

        ANP_NS="anp-restricted anp-open anp-unknown anp-test anp-node"

        for ns in $ANP_NS
        do
            #  export CUSTOMIZED_WORKLOAD_FILE=./customized-workload.yml
             #POD_SECLECTOR_ANP_NS_NUM will create 5 X ITERATION NS for pod selctor ANP.
             #We define 4 group of NS for pod selector ANP, each NS will have 4 pods, 4 service, 1 route by default
             export CUSTOMIZED_ITERATIONS=$ITERATIONS
  
             create_customized_workload $ns workload
             append_customized_workload4Pods $ns postgres-deployment.yml
             append_customized_workload4Service $ns postgres-service.yml
             append_customized_workload4Pods $ns perfapp-deployment.yml
             append_customized_workload4Service $ns perfapp-clusterip-service.yml
            #  append_customized_workload4Service $ns perfapp-nodeport-service.yml
             append_customized_workload4Pods $ns egress-traffic-app.yml
             append_customized_workload4Pods $ns perfweb-deployment.yml
             append_customized_workload4Service $ns perfweb-ingress-service.yml
             append_customized_workload_without_inputvar perfweb-ingress-route.yaml


             if [[ ${ENABLE_NETWORK_POLICY} == "true" && ${NO_VERIFY_ANP} == "true" && ${IF_ONLY_ANP} == "false" ]];then
                 create_large_scale_network_policy $ns true
             fi
                          
             if [[ ${ENABLE_EGRESS_FIREWALL_POLICY} == "true" ]];then
                   EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=./egress-firewall-policy.yml
                   generated_egress_firewall_policy $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM
                   cat ./egress-firewall-policy.yml
                   append_customized_workload_without_inputvar egress-firewall-policy.yml
             fi
             cat $CUSTOMIZED_WORKLOAD_FILE
             echo  ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
             ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml       
        done

        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo "Create Pods for CIDR Selector ANP"
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        ANP_NS="anp-cidr anp-pcidr"

        for ns in $ANP_NS
        do
            #  export CUSTOMIZED_WORKLOAD_FILE=./customized-workload.yml
             #POD_SECLECTOR_ANP_NS_NUM will create 6 X ITERATION NS for CIDR selctor ANP.
             #We define 2 group NS for CIDR selector ANP, each NS will have 4 pods, 4 service, 1 route by default
             export CUSTOMIZED_ITERATIONS=$(( $ITERATIONS * 2 ))
  
             create_customized_workload $ns workload
             append_customized_workload4Pods $ns postgres-deployment.yml
             append_customized_workload4Service $ns postgres-service.yml
             append_customized_workload4Pods $ns perfapp-deployment.yml
             append_customized_workload4Service $ns perfapp-clusterip-service.yml
             append_customized_workload4Pods $ns egress-traffic-app.yml
             append_customized_workload4Pods $ns perfweb-deployment.yml
             append_customized_workload4Service $ns perfweb-ingress-service.yml
             append_customized_workload_without_inputvar perfweb-ingress-route.yaml


             if [[ ${ENABLE_NETWORK_POLICY} == "true" && ${NO_VERIFY_ANP} == "true" && ${IF_ONLY_ANP} == "false" ]];then
                 create_large_scale_network_policy $ns true
             fi

             if [[ ${ENABLE_EGRESS_FIREWALL_POLICY} == "true" ]];then
                   EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=./egress-firewall-policy.yml
                   generated_egress_firewall_policy $EGRESS_FIREWALL_POLICY_RULES_TOTAL_NUM
                   cat ./egress-firewall-policy.yml
                   append_customized_workload_without_inputvar egress-firewall-policy.yml
             fi
             cat $CUSTOMIZED_WORKLOAD_FILE
             echo  ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml
             ${KUBE_DIR}/kube-burner-ocp init --uuid=${UUID} --qps=${QPS} --burst=${BURST} --gc=${GC} --churn=${CHURN} --config=customized-workload.yml       
        done

        #Create Customized Ingress Controller 
        if [[ ${ENABLE_INGRESS_CONTROLLER} == "true" ]]; then             
              create_ingress_controller               
        fi    

        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo "All perfscale workload created and ready to test"
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'        
        export QUERY_TIME=`date +"%y-%m-%d %H:%M:%S.%N" -d "+8 hours"` 
        get_ovn_node_system_usage_info
      
        create_large_scale_anp_networkpolicy_egressfirewall_policy
 
        #Because NetworkPolicy will override the ANP policy, so we need to create the ANP policy before NetworkPolicy
        #Another choice is to create the NetworkPolicy and ANP policy, but don't need to verify if ANP and NetowrkPolicy are working as expected
        if [[ ${ENABLE_NETWORK_POLICY} == "true" && ${NO_VERIFY_ANP} == "false" && ${IF_ONLY_ANP} == "false" ]];then
            
            awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
            echo "Creating Large Scale Network Policy"
            awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'


            NS_LIST="anp-restricted anp-open anp-unknown anp-test anp-node"
            export CUSTOMIZED_ITERATIONS=$ITERATIONS
            for ns in $NS_LIST
            do
                create_large_scale_network_policy $ns false
            done
  
            NS_LIST="anp-cidr anp-pcidr"
            export CUSTOMIZED_ITERATIONS=$(( $ITERATIONS * 2 ))
            for ns in $NS_LIST
            do
                create_large_scale_network_policy $ns false
            done
        fi
        cd ..  

        waiting_for_during_each_phase "Phase II" 1800 "after creating large scale ANP/NetworkPolicy/EgressFirewall" false

        JOB_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ");
        env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh
        echo
       
        #compare_with_baseline        
        #TBD
        
        if [[ ${IF_SCALE_NODE_TESTING} == "true" ]];then
            scale_out_down_nodes
            waiting_for_during_each_phase "Scaling Out/Down Phase" 900 "after recycle node pods" true
        fi
        
        if [[ ${IF_RECYCLE_NODE_TESTING} == "true" ]];then
            recycle_worker_node
            waiting_for_during_each_phase "Recycle Node Phase" 900 "after recycle worker node" true
        fi

        if [[ ${RESTART_OVN_PODS} == "true" ]];then
            restartOVNPODs
            waiting_for_during_each_phase "Restart OVN Pods Phase" 900 "after restart OVN pods" true
        fi

        if [[ ${IF_NETPOL_SYNC_CHECKING} == "true" ]];then
            cd customized-workloads
            networkPolicyInitSyncDurationCheck
            cd ..
        fi
        
        cat /tmp/system_resource_info.csv

        JOB_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ");
        env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh
        
        START_TIME=$(date -d "$JOB_START" +%s)
        END_TIME=$(date -d "$JOB_END" +%s)
        ${KUBE_DIR}/kube-burner-ocp index --uuid=${UUID} --start=$START_TIME --end=$((END_TIME + 600)) --metrics-profile=$METRICS_PROFILE --log-level ${LOG_LEVEL}

        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo "Compare the benchmarking result with the baseline after executing all testing"
        awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
        echo 
        generate_sys_resource_usage_report $JOB_START $JOB_END true
        get_ovn_node_system_usage_info
        
        #Rollback 
        oc scale deployment cluster-version-operator -n openshift-cluster-version --replicas=1
        oc scale deployment network-operator -n openshift-network-operator --replicas=1
        waiting_for_during_each_phase "Final Phase:" 300 "after rollback cluster-version-operator and network-operator" false

        #ovnkube_controller_admin_network_policies
        #sum by(action, direction, pod) (ovnkube_controller_admin_network_policies_rules)

        #TBD, with issue when import dashboard json file
        # if [[ $IF_DEPLOY_CUSTOMIZED_DASHBOARD == "true" ]];then
        #         DITTYBOPPER_PARAMS="-i customized-workloads/customized-ovn-dashboard.json"
        #         git clone https://github.com/cloud-bulldozer/performance-dashboards.git
        #         performance-dashboards/dittybopper/deploy.sh $DITTYBOPPER_PARAMS
        
        #         dittybopper_route=$(oc -n dittybopper get route dittybopper  -o jsonpath="{.spec.host}")

        #         dashboard_request="{\"dashboard\": ${dashboard}, \"overwrite\": true}"
        #         response_code=$(curl -Ss -w "%{http_code}" -X POST -H "Content-Type: application/json" -H "Accept: application/json" -d "${dashboard_request}" \
        #         "http://admin:admin@${dittybopper_route}/api/dashboards/db" -o /tmp/resp.txt)
                
        # fi  

fi

exit_code=$?
if [ $exit_code -eq 0 ]; then 
  JOB_STATUS="success"
else
  JOB_STATUS="failure"
fi
echo The job is $JOB_STATUS

