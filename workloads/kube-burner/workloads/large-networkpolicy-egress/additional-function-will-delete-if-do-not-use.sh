function generated_anp_cidr_1ips_perrule_multi_policy_bynsgroup(){
    
    TARGET_NS_PREFIX=$1
    PRIORITY=99  #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress

    if [[ -z $TARGET_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX $TARGET_NS_PREFIX
            exit 1
    fi

    TARGET_NS=`oc get ns |grep -w $TARGET_NS_PREFIX | awk '{print $1}'`
    if [[ -z $TARGET_NS ]];then
            echo "No TARGET_NS_PREFIX $TARGET_NS_PREFIX was found"
            exit 1
    fi

INIT=1
    for ns in $TARGET_NS
    do
            POD_IPs=`oc -n $ns get pods -owide |grep app | awk '{print $6}'`
            for pod_ip in $POD_IPs
            do
            REMAINDER=$(( $INIT % 100 ))
            FILESN=$(( $INIT / 100 ))
            echo REMAINDER is $REMAINDER FILESN is $FILESN
            if [[ $REMAINDER -eq 1 ]];then
                PRIORITY=$(( $PRIORITY - $FILESN ))
                echo PRIORITY is $PRIORITY
                if [[ $PRIORITY -lt 0 ]];then
                     echo "unsupported priority $PRIORITY, the max capacity(10k anp) of anp reached, maximize 40k pods, please check"
                     exit 1
                fi        
cat>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-egress-cidr-anp-open-network-p${PRIORITY}
spec:
  priority: ${PRIORITY}
  subject:
    namespaces:
      matchLabels:
        anplabel: anp-cidr
  egress: 
EOF
            fi            
               echo -e "  - name: \"allow-egress-to-anp-open-network-${INIT}\"\n    action: \"Allow\"\n    ports:\n      - portNumber:\n          port: 8080\n          protocol: TCP\n    to:\n    - networks:\n      - ${pod_ip}/32">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml
               INIT=$(( $INIT + 1 ))
            done
    done

    #oc -n openshift-kube-apiserver get pods -owide |grep kube-apiserver | awk '{print $6}'
    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done
    echo "---------------------------------------------------------------------------------"
    oc get anp | grep allow-traffic-egress-cidr-anp-open-network-p
    TOTAL_ANP=`oc get anp | grep allow-traffic-egress-cidr-anp-open-network-p|wc -l`
    echo "---------------------------------------------------------------------------------"
    echo "The total anp is $TOTAL_ANP"
    echo
}

function generated_anp_cidr_100ip_perpolicyrule_bynsgroup(){
    
    TARGET_NS_PREFIX=$1
    PRIORITY=99  #Max priority is 99
    WORKLOAD_TEMPLATE_PATH=workloads/large-networkpolicy-egress

    if [[ -z $TARGET_NS_PREFIX ]];then
            echo please specify TARGET_NS_PREFIX $TARGET_NS_PREFIX
            exit 1
    fi

    TARGET_NS=`oc get ns |grep -w $TARGET_NS_PREFIX | awk '{print $1}'`
    if [[ -z $TARGET_NS ]];then
            echo "No TARGET_NS_PREFIX $TARGET_NS_PREFIX was found"
            exit 1
    fi

INIT=1
    for ns in $TARGET_NS
    do
            POD_IPs=`oc -n $ns get pods -owide |grep app | awk '{print $6}'`
            for pod_ip in $POD_IPs
            do
            REMAINDER=$(( $INIT % 100 ))
            FILESN=$(( $INIT / 100 ))
            echo REMAINDER is $REMAINDER FILESN is $FILESN
            if [[ $REMAINDER -eq 1 ]];then
                PRIORITY=$(( $PRIORITY - $FILESN ))
                echo PRIORITY is $PRIORITY
                if [[ $PRIORITY -lt 0 ]];then
                     echo "unsupported priority $PRIORITY, the max capacity(10k anp) of anp reached, maximize 40k pods, please check"
                     exit 1
                fi        
cat>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-egress-cidr-anp-open-network-p${PRIORITY}
spec:
  priority: ${PRIORITY}
  subject:
    namespaces:
      matchLabels:
        anplabel: anp-cidr
  egress:
  - name: "allow-egress-to-anp-open-network"
    action: "Allow"
    ports:
      - portNumber:
          port: 8080
          protocol: TCP 
      - portRange:
          start: 9100
          end: 9105
          protocol: TCP            
    to:
 
EOF
            fi            
               echo -e "   - networks:\n      - ${pod_ip}/32">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml
               INIT=$(( $INIT + 1 ))
            done
    done

    #oc -n openshift-kube-apiserver get pods -owide |grep kube-apiserver | awk '{print $6}'
    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    oc get anp | grep allow-traffic-egress-cidr-anp-open-network-p
    TOTAL_ANP=`oc get anp | grep allow-traffic-egress-cidr-anp-open-network-p|wc -l`
    awk 'BEGIN{for(c=0;c<80;c++) printf "-"; printf "\n"}'
    echo "The total anp is $TOTAL_ANP"
    echo
}

function generated_anp_cidr_25ips_multi_rules_multipolicy_bytenant(){
    #Create multiple anp
    #Each ANP contains multi rules
    #25 IPs per rule 
    SOURCE_NS_PREFIX=$1
    TARGET_NS_PREFIX=$2
    PRIORITY=40 #Max priority is 99
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

    >${WORKLOAD_TEMPLATE_PATH}/map-tenant-ips.lst
    INIT=1
    TENANT_ID=1
    NODE_INDEX=1
    RULE_INDEX=1
    for sns in $SOURCE_NS
    do      
            tns=`echo $sns | sed "s/${SOURCE_NS_PREFIX}/${TARGET_NS_PREFIX}/"`
            # 4 ns per tenant
            IF_NEW_TENANT=$(( $INIT % 4 ))
            oc label ns $sns customer_tenat=tenant${TENANT_ID}
            echo oc label ns $sns customer_tenat=tenant${TENANT_ID}
            if [[ -z $tns ]];then
                 echo "No target ns was found inside generated_anp_cidr_25ips_multi_rules_multipolicy_bytenant, please check "
            fi             

            POD_IPs=`oc -n $tns get pods -owide |grep app | awk '{print $6}'`
            for pod_ip in $POD_IPs
            do
            IF_NEW_POLICY=$(( $INIT % 250 ))
            PRIORITY_STEP=$(( $INIT / 250 ))

            IF_NEW_RULE=$(( $INIT % 25 ))
            RULE_STEP=$(( $INIT / 25 ))
            echo IF_NEW_RULE is $IF_NEW_RULE IF_NEW_RULE is $IF_NEW_RULE
            if [[ $IF_NEW_POLICY -eq 1 || $IF_NEW_TENANT -eq 1 ]];then
                PRIORITY=$(( $PRIORITY + $PRIORITY_STEP ))
                echo PRIORITY is $PRIORITY
                if [[ $PRIORITY -gt 69 ]];then
                     echo "limited priority $PRIORITY to 69, the max anp of cidr selector is 30, please check"
                     break
                fi        
cat>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml<<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-traffic-egress-cidr-anp-open-network-tenant${TENANT_ID}-p${PRIORITY}
spec:
  priority: ${PRIORITY}
  subject:
    namespaces:
      matchLabels:
        customer_tenat: tenant${TENANT_ID}
  egress:  
EOF
              PRIORITY=$(( $PRIORITY + 1 ))
              TENANT_ID=$(( $TENANT_ID + 1 ))
            fi

            if [[ $IF_NEW_RULE -eq 1 ]];then
               echo -e "  - name: \"allow-egress-to-anp-open-network-${RULE_INDEX}\"\n    action: \"Allow\"\n    ports:\n      - portNumber:\n          port: 8080\n          protocol: TCP\n    to:\n    - networks:">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml
               RULE_INDEX=$(( $RULE_INDEX + 1 ))
            fi
               echo -e "      - ${pod_ip}/32">>${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-p${PRIORITY}.yaml
               INIT=$(( $INIT + 1 ))
            done
    done

    #oc -n openshift-kube-apiserver get pods -owide |grep kube-apiserver | awk '{print $6}'
    for yamlfile in `ls ${WORKLOAD_TEMPLATE_PATH}/18_anp_allow-traffic-egress-cidr-open-network-*.yaml`
    do
        oc apply -f $yamlfile
        printYAMLFile $yamlfile
    done
    echo "---------------------------------------------------------------------------------"
    oc get anp | grep allow-traffic-egress-cidr-anp-open-network-p
    TOTAL_ANP=`oc get anp | grep allow-traffic-egress-cidr-anp-open-network-p|wc -l`
    echo "---------------------------------------------------------------------------------"
    echo "The total anp is $TOTAL_ANP"
    echo
}
