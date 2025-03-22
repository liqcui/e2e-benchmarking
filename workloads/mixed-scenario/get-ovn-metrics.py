#!/usr/bin/env python3
import argparse
import elasticsearch
import subprocess
import json
import requests
import urllib3
from datetime import datetime
import math
import uuid
import os
import ast
import ssl

# es_server = os.getenv("ES_SERVER")
# es_index = os.getenv("ES_INDEX")
# def index_result(payload, retry_count=3):
#     # Environment vars
#     print(f"Indexing documents in {es_index}")
#     while retry_count > 0:
#         try:
#             ssl_ctx = ssl.create_default_context()
#             ssl_ctx.check_hostname = False
#             ssl_ctx.verify_mode = ssl.CERT_NONE
#             es = elasticsearch.Elasticsearch([es_server], send_get_body_as='POST',ssl_context=ssl_ctx, use_ssl=True)
#             print("#"*118)
#             print("ES Information: \n{}".format(es.info()))
#             print("#"*118)
#             print()
#             es.index(index=es_index, body=payload,doc_type='doc')

#             retry_count = 0
#         except Exception as e:
#             print("Failed Indexing - \n" + str(e.with_traceback))
#             print("Retrying again to index...")
#             retry_count -= 1

'''Getting token to access prometheus api'''
# Invokes a given command and returns the stdout
def invokecmd(command):

    try:
        cmdStdOut = subprocess.check_output(command, shell=True, universal_newlines=True,stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        print("Status: execute {} failure, return code is {}, Error message:\n {}".format(command,exc.returncode,exc.stderr))
        return exc.returncode,exc.stderr
    return 0, cmdStdOut

def get_sa_token():

    returnCode,cmdStdOut = invokecmd('oc create token -n openshift-monitoring prometheus-k8s')

    if returnCode and cmdStdOut.find("unknown command"):
        print("oc create token -n openshift-monitoring prometheus-k8s is unknown command, try another command")
        returnCode, cmdStdOut = invokecmd('oc sa new-token -n openshift-monitoring prometheus-k8s')
        if returnCode:
            print("Fail to get the token for sa  prometheus-k8s, please check")
            exit(1)
    return returnCode,cmdStdOut

def getTimeDuration(start_time, end_time):

    time1 = datetime.fromtimestamp(start_time)
    time2 = datetime.fromtimestamp(end_time)
    #Return how long minutes duration
    return math.ceil((time2 - time1).total_seconds() / 60)

def convertStr2Time(time_str):
  
    try:

        # Convert to time format from string
        dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")

        # Convert to unix timestamp      
        unix_timestamp_sec = int(dt.timestamp())
        print(f"Convert {dt} to Unix Timestamp (Seconds): {unix_timestamp_sec}")
        return unix_timestamp_sec
    except ValueError as e:
        print(f"Error: {e}")

def get_ovn_metrics(metricName, start_time, end_time, promQLOperation):
        if start_time >= end_time:
            print("End time must great than start time")
            exit(1)
        returnCode,token = get_sa_token()
        if returnCode:
            print("Fail to get the token for sa prometheus-k8s, please check")
            exit(1)

        returnCode,prometheusURL=invokecmd('oc get route -n openshift-monitoring prometheus-k8s -o jsonpath="{.spec.host}"')
        if returnCode:
             print("Fail to get prometheus URL")
             exit(1)

        #Define variable
        promQL=''
        requestMetricUrl=''       
        timeDuration = getTimeDuration(start_time, end_time)
        if 0< timeDuration <= 30:
          timeDuration="30m"
        elif 30< timeDuration < 60:
          timeDuration=str(timeDuration)+"m"  
        elif timeDuration >= 60:
           timeDuration=math.ceil( timeDuration / 60)
           timeDuration=str(timeDuration)+"h"
        else:
            print("Invalid timeDuration")
            exit


        print("#" * 118)
        print("Query {} data from {} to {}, time duration is {} (Min/Hour)".format(promQL,datetime.fromtimestamp(start_time),datetime.fromtimestamp(end_time),timeDuration))
        print("#" * 118)
        print()
        promQueryAPIURL = "https://"+prometheusURL+"/api/v1/query?query="
        if promQLOperation == "topMaxOverTime":
            promQL = "topk(10, max_over_time({}[{}]))".format(metricName, timeDuration)
        elif promQLOperation == "histogramQuantile":
            promQL = "histogram_quantile(0.9, sum by(pod, event, le) (rate({}[5m])))".format(metricName)
        else:
            print("Unsupported prom QL operations, support type is: topMaxOverTime and histogramQuantile")
        print("-" * 118)
        print(promQL)
        print("-" * 118)
        requestMetricUrl=promQueryAPIURL + promQL


        #Disable InsecureRequestWarning: Unverified HTTPS request is being made.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        prom_metrics=requests.post(url=requestMetricUrl, headers={'Authorization': 'Bearer {}'.format(token)},verify=False).content.decode('utf8', 'ignore')
        # print(prom_metrics)

        prom_metrics_json=json.loads(prom_metrics)
        # print("The metrics of {} in prometheus:\n{}\n{}".format(promQL,"-" * 118,prom_metrics_json))
        # print("-" * 118)
        # print()

        
        print("MetricName"+" " * 80+" "+"PodName/ResourceName"+" " * 20+"Value")
        print("=" * 118)
        payload=generatedPayload()
              
        results = prom_metrics_json['data']['result']
        i=1
        for r in results:
            # print(r)
            if "ovnkube_controller_pod_event_latency_seconds_bucket" in promQL:
               #metricName="ovnkube_controller_pod_event_latency_seconds_bucket"
               metricEvent=r['metric']['event']
            #    print(metricEvent)
            # else:
            #     metricName=promQL
            # elif "max_over_time" in promQL:
            #    metricName=promQL
            # else:
            #    metricName=r['metric']['__name__']

            #metricName=promQL
            podName=r['metric']['pod']
            # instanceName=r['metric']['instance']
            
            resourceName=""
            if "ovnkube_controller_sync_duration_seconds" in promQL:
                resourceName=r['metric']['resource_name']

            metricValue=float(r['value'][1])
            if math.isnan(metricValue): 
               metricValue=float(0)            
            payload["metric"]=metricName
            if "ovnkube_controller_sync_duration_seconds" in promQL:
              payload[podName+":"+resourceName]=metricValue
              print("No."+str(i)+" "+metricName+',    '+podName+":"+resourceName+',    '+str(metricValue))
            elif "ovnkube_controller_pod_event_latency_seconds_bucket" in promQL:
              payload[podName+":"+metricEvent]=metricValue
              print("No."+str(i)+" "+metricName+',    '+podName+":"+metricEvent+',    '+str(metricValue))
            else:
              payload[podName]=metricValue
              print("No."+str(i)+" "+metricName+',    '+podName+',    '+str(metricValue))
            i +=1
            
        print()
        print("The payload will save to elasticsearch:\n{}\n{}".format("-" * 118,payload))
        print("-" * 118+'\n')

        payload_json = json.dumps(payload, indent=4)
        try:
           with open("ovn-metric-es-payload.json", "w") as file:
             file.write(payload_json)
        except IOError as e:
           print(f"An error occurred: {e}")
        
        # #save to elasticsearch
        # if es_server != None:
        #    currentTime=datetime.now()
        #    payload["timestamp"] = currentTime
        #    index_result(payload)
        return payload

def generatedPayload():
        payload={}
        currentTime=datetime.now()
        job_name = os.getenv("WORKLOAD")
        total_workload = os.getenv("ITERATIONS")
        get_timestamp_uuid = os.getenv("UUID")
        cluster_id = os.getenv("CLUSTER_ID", "")

        returnCode,cluster_id=invokecmd("oc get clusterversion -o jsonpath='{.items[].spec.clusterID}'")
        if returnCode:
            print("Fail to get cluster id, please check")
            exit(1)           

        returnCode,cluster_name=invokecmd("oc config view -ojsonpath={.clusters[0].name}")
        if returnCode:
            print("Fail to get cluster name, please check")
            exit(1)
        returnCode,openshift_version=invokecmd("oc get clusterversion -ojsonpath={.items[*].status.desired.version}")
        if returnCode:
            print("Fail to get cluster version, please check")
            exit(1)

        returnCode, kubernetes_version = invokecmd("oc version --client=false |grep 'Kubernetes Version:'| awk -F: '{print $2}'")
        if returnCode:
            print("Fail to get cluster name, please check")
            exit(1)
        
        network_type = os.getenv("CLUSTER_NETWORK_TYPE", "")
        returnCode, network_type = invokecmd("oc get network cluster -ojsonpath={.status.networkType}")
        if returnCode:
            print("Fail to get network type, please check")
            exit(1)

        returnCode,total_workernode=invokecmd("oc get nodes -lnode-role.kubernetes.io/worker= --no-headers|wc -l")
        if returnCode:
            print("Fail to get total worker nodes, please check")
            exit(1)
        returnCode,cluster_platform=invokecmd("oc get infrastructure cluster -ojsonpath='{.status.platformStatus.type}'")
        if returnCode:
            print("Fail to get cluster infrastructure, please check")
            exit(1)

        payload["name"]=job_name
        payload["workload"]=int(total_workload)
        payload["workernode"]=int(total_workernode)
        payload["uuid"]=get_timestamp_uuid
        payload["cluster.id"]=cluster_id
        payload["cluster.name"] = cluster_name
        payload["cluster.ocp_version"] = openshift_version
        payload["cluster.kubernetes_version"] = kubernetes_version
        payload["cluster.sdn"] = network_type
        payload["cluster.platform"] = cluster_platform
 
        return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q",
        "--query",
        help="PromQL query string",
        required=True,
        type=str,
    )
    parser.add_argument(
        "-s",
        "--start_time",
        help="Start Time: 2025-03-18T07:00:00Z",
        required=True,
        type=str,
    )
    parser.add_argument(
        "-e",
        "--end_time",
        help="End Time: 2025-03-18T10:00:00Z",
        required=True,
        type=str,
    )
    parser.add_argument(
        "-t",
        "--metric_operations",
        help="metric_operations support type is: topMaxOverTime and histogramQuantile",
        required=True,
        type=str,
    )
     

    args = parser.parse_args()
    unixStartTime=convertStr2Time(args.start_time)
    unixEndTime=convertStr2Time(args.end_time)

    get_ovn_metrics(args.query,int(unixStartTime), int(unixEndTime),args.metric_operations)
