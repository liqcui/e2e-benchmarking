#    echo "#####################################################################"
#https://docs.openshift.com/container-platform/4.16/nodes/clusters/nodes-cluster-enabling-features.html
#https://docs.openshift.com/container-platform/4.16/scalability_and_performance/recommended-performance-scale-practices/recommended-etcd-practices.html#etcd-increase-db_recommended-etcd-practices
#
# oc apply -f-<<EOF
# apiVersion: config.openshift.io/v1
# kind: FeatureGate
# metadata:
#  annotations:
#    release.openshift.io/create-only: "true"
#  name: cluster
# spec:
#  featureSet: EtcdBackendQuota
# EOF

#    oc patch etcd/cluster --type=merge -p '{"spec": {"backendQuotaGiB": 16}}'
#    echo "#####################################################################"