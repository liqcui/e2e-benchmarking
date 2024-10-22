#!/usr/bin/bash

. common.sh
. build_helper.sh
. ../../utils/compare.sh

label=""
case ${WORKLOAD} in
  cluster-density)
    WORKLOAD_TEMPLATE=workloads/cluster-density/cluster-density.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-aggregated.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-1000}
  ;;
  node-density)
    WORKLOAD_TEMPLATE=workloads/node-pod-density/node-pod-density.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    NODE_COUNT=${NODE_COUNT:-$(kubectl get node -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= -o name | wc -l)}
    PODS_PER_NODE=${PODS_PER_NODE:-245}
    label="node-density=enabled"
    label_node_with_label $label
    find_running_pods_num regular
  ;;
  node-density-heavy)
    WORKLOAD_TEMPLATE=workloads/node-density-heavy/node-density-heavy.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    NODE_COUNT=${NODE_COUNT:-$(kubectl get node -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= -o name | wc -l)}
    PODS_PER_NODE=${PODS_PER_NODE:-245}
    export NAMESPACED_ITERATIONS=${NAMESPACED_ITERATIONS:-false}
    label="node-density=enabled"
    label_node_with_label $label
    find_running_pods_num heavy
  ;;
  node-density-cni)
    WORKLOAD_TEMPLATE=workloads/node-density-cni/node-density-cni.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    NODE_COUNT=${NODE_COUNT:-$(kubectl get node -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= -o name | wc -l)}
    PODS_PER_NODE=${PODS_PER_NODE:-245}
    export NAMESPACED_ITERATIONS=${NAMESPACED_ITERATIONS:-false}
    label="node-density=enabled"
    label_node_with_label $label
    find_running_pods_num cni
  ;;
  node-density-cni-networkpolicy)
    WORKLOAD_TEMPLATE=workloads/node-density-cni-networkpolicy/node-density-cni-networkpolicy.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    NODE_COUNT=${NODE_COUNT:-$(kubectl get node -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= -o name | wc -l)}
    PODS_PER_NODE=${PODS_PER_NODE:-245}
    label="node-density=enabled"
    label_node_with_label $label
    find_running_pods_num cni
  ;;
  pod-density)
    WORKLOAD_TEMPLATE=workloads/node-pod-density/node-pod-density.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    export TEST_JOB_ITERATIONS=${PODS:-1000}
  ;;
  pod-density-heavy)
    WORKLOAD_TEMPLATE=workloads/pod-density-heavy/pod-density-heavy.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    NODE_COUNT=${NODE_COUNT:-$(kubectl get node -l ${WORKER_NODE_LABEL},node-role.kubernetes.io/infra!=,node-role.kubernetes.io/workload!= -o name | wc -l)}
    PODS_PER_NODE=${PODS_PER_NODE:-245}
    label="pod-density-heavy=enabled"
    label_node_with_label $label
    find_running_pods_num regular
  ;;
  pods-service-route)
    WORKLOAD_TEMPLATE=workloads/pods-service-route/pods-service-route.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    export TEST_JOB_ITERATIONS=${NAMESPACE_COUNT:-1000}
  ;;
  max-namespaces)
    WORKLOAD_TEMPLATE=workloads/max-namespaces/max-namespaces.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-aggregated.yaml}
    export TEST_JOB_ITERATIONS=${NAMESPACE_COUNT:-1000}
  ;;
  max-services)
    WORKLOAD_TEMPLATE=workloads/max-services/max-services.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-aggregated.yaml}
    export TEST_JOB_ITERATIONS=${SERVICE_COUNT:-1000}
  ;;
  concurrent-builds)
    rm -rf conc_builds_results.out
    WORKLOAD_TEMPLATE=workloads/concurrent-builds/concurrent-builds.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-aggregated.yaml}
    export build_test_repo=${BUILD_TEST_REPO:=https://github.com/openshift/svt.git}
    export build_test_branch=${BUILD_TEST_BRANCH:=master}
    install_svt_repo
    export build_array=($BUILD_LIST)
    label="concurrent-builds=enabled"
    label_node_with_label $label
    max=1
    for v in ${build_array[@]}; do
        if (( $v > $max )); then
          max=$v
        fi
    done
    export MAX_CONC_BUILDS=$((max + 1))
    export TEST_JOB_ITERATIONS=${MAX_CONC_BUILDS:-$max}
  ;;
  cluster-density-ms)
    WORKLOAD_TEMPLATE=workloads/managed-services/cluster-density.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/hypershift-metrics.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-75}
  ;; 
  networkpolicy-case1)
    WORKLOAD_TEMPLATE=workloads/networkpolicy/case1.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-ovn.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-500}
    prep_networkpolicy_workload
  ;;
  networkpolicy-case2)
    WORKLOAD_TEMPLATE=workloads/networkpolicy/case2.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-ovn.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-5}
    prep_networkpolicy_workload
  ;;
  networkpolicy-case3)
    WORKLOAD_TEMPLATE=workloads/networkpolicy/case3.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-ovn.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-5}
    prep_networkpolicy_workload
  ;;
  large-networkpolicy-egress)
    EGRESS_FIREWALL_POLICY_TEMPLAT_FILE_PATH=workloads/large-networkpolicy-egress/engress-firewall.yaml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics-ovn.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-5}
    generated_egress_firewall_policy
    prep_networkpolicy_workload
  ;;
  ovn-live-migration)
    WORKLOAD_TEMPLATE=workloads/ovn-live-migration/case-live-migration-pods.yml
    METRICS_PROFILE=${METRICS_PROFILE:-metrics-profiles/metrics.yaml}
    export TEST_JOB_ITERATIONS=${JOB_ITERATIONS:-1}
    export POD_RPLICAS=${POD_RPLICAS:=6}
    export ONLY_POST_CHECKING=${ONLY_POST_CHECKING:="false"}
  ;;
  custom)
  ;;
  *)
     log "Unknown workload ${WORKLOAD}, exiting"
     exit 1
  ;;
esac

cat << EOF
###############################################
Workload: ${WORKLOAD}
Workload template: ${WORKLOAD_TEMPLATE}
Metrics profile: ${METRICS_PROFILE}
Alerts profile: ${ALERTS_PROFILE}
QPS: ${QPS}
Burst: ${BURST}
UUID: ${UUID}
EOF
JOB_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
if [[ ${WORKLOAD} == node-density* || ${WORKLOAD} == pod-density-heavy ]]; then
  echo "Node count: ${NODE_COUNT}"
  echo "Pods per node: ${PODS_PER_NODE}"
else
  echo "Job iterations: ${TEST_JOB_ITERATIONS}"
fi
echo "###############################################"
if [[ ${PPROF_COLLECTION} == "true" ]] ; then
  delete_pprof_secrets
  delete_oldpprof_folder
  get_pprof_secrets
fi

if [[ ${WORKLOAD} == "concurrent-builds" ]]; then
   app_array=($APP_LIST)
   for app in "${app_array[@]}"
   do
      run_build_workload $app
   done
   unlabel_nodes_with_label $label
   cat conc_builds_results.out
elif [[ ${WORKLOAD} == "large-networkpolicy-egress" ]]; then
   run_large_networkpolicy_egressfirewall_anp_workload
elif [[ ${WORKLOAD} == "ovn-live-migration" ]];then
   if [[ ${EnableIndex} == "true" ]];then
       enable_kube_burner_index
   fi
   if [[ $ONLY_POST_CHECKING == "false" ]];then
        LABEL_NODE=`oc get nodes |grep worker | awk '{print $1}' | head -1`
        oc label node $LABEL_NODE node-role.kubernetes.io/backend=
        run_workload
        export TEST_JOB_ITERATIONS=1
        WORKLOAD_TEMPLATE=workloads/ovn-live-migration/case-large-networkpolicy-egress-restricted.yml
        run_workload
        unset  TEST_JOB_ITERATIONS
        live-migration-keepalive-detect
        sleep 180
        live-migration-post-check
        if [[ ${EnableIndex} == "true" ]];then
           sleep 900
           enable_kube_burner_index
          #  echo "#######################################################"
          #  NW_MIGRATION_DURATION=$((NW_MIGRATION_STOP - NW_MIGRATION_START - 300))
          #  export AFTER_N_TYPE=$(oc get Network.operator.openshift.io cluster  -o json | jq -r '.spec.defaultNetwork.type')
          #  sdn2ovn_index_results "$BEFORE_N_TYPE" "$AFTER_N_TYPE" "$NW_MIGRATION_DURATION" "$OPENSHIFT_VERSION"           
        fi
   else
         live-migration-post-check
         if [[ ${EnableIndex} == "true" ]];then
           enable_kube_burner_index
          #  echo "#######################################################"
          #  NW_MIGRATION_DURATION=$((NW_MIGRATION_STOP - NW_MIGRATION_START - 300))
          #  export AFTER_N_TYPE=$(oc get Network.operator.openshift.io cluster  -o json | jq -r '.spec.defaultNetwork.type')
          #  sdn2ovn_index_results "$BEFORE_N_TYPE" "$AFTER_N_TYPE" "$NW_MIGRATION_DURATION" "$OPENSHIFT_VERSION"
         fi
   fi
else
   run_workload
fi
JOB_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
if [[ ${CLEANUP_WHEN_FINISH} == "true" ]]; then
  cleanup
  if [[ ${WORKLOAD} == node-density* || ${WORKLOAD} == pod-density-heavy ]]; then
    unlabel_nodes_with_label $label
  fi
fi
delete_pprof_secrets
if [[ ${ENABLE_SNAPPY_BACKUP} == "true" ]] ; then
  tar czf pprof.tar.gz ./pprof-data
  snappy_backup "" "pprof.tar.gz" ${WORKLOAD}
fi

if [[ ${WORKLOAD} != "ovn-live-migration" ]];then
    run_benchmark_comparison
fi

if [ $rc -eq 0 ]; then
  JOB_STATUS="success"
else
  JOB_STATUS="failure"
fi
env JOB_START="$JOB_START" JOB_END="$JOB_END" JOB_STATUS="$JOB_STATUS" UUID="$UUID" WORKLOAD="$WORKLOAD" ES_SERVER="$ES_SERVER" ../../utils/index.sh
exit ${rc}
