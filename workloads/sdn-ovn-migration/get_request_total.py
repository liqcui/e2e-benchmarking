#!/usr/bin/env python3
import argparse
import subprocess
import json
import requests
import urllib3
from datetime import datetime
import math
import os
import sys

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
        #print(f"Convert {dt} to Unix Timestamp (Seconds): {unix_timestamp_sec}")
        return unix_timestamp_sec
    except ValueError as e:
        print(f"Error: {e}")

def format_output_alligin_colums(reportData,columNum):
    # Determine the width of each column

    if columNum == 2:
        metric_name_width = max(len(row[0]) for row in reportData)
        value_width = max(len(row[1]) for row in reportData)
        # Print the table
        for index,row in enumerate(reportData):
           if index==0:
              print(f"{row[0].ljust(metric_name_width)}    {row[1].ljust(value_width)}")
              print("-" * metric_name_width+"----"+"----"+"-" * value_width)
           else:
              print(f"{row[0].ljust(metric_name_width)}    {row[1].ljust(value_width)}")

    elif columNum == 3:
        metric_name_width = max(len(row[0]) for row in reportData)
        resource_name_width = max(len(str(row[1])) for row in reportData)
        value_width = max(len(row[2]) for row in reportData)
        # Print the table
        for index,row in enumerate(reportData):
           if index==0:
              print(f"{row[0].ljust(metric_name_width)}    {str(row[1]).ljust(resource_name_width)}    {row[2].ljust(value_width)}")
              print("-" * metric_name_width+"----"+"-" * resource_name_width+"----"+"-" * value_width)
           else:
              print(f"{row[0].ljust(metric_name_width)}    {str(row[1]).ljust(resource_name_width)}    {row[2].ljust(value_width)}")

    elif columNum == 4:
        metric_name_width = max(len(row[0]) for row in reportData)
        node_name_width = max(len(str(row[1])) for row in reportData)
        resource_name_width = max(len(row[2]) for row in reportData)
        value_width = max(len(row[3]) for row in reportData)
        for index,row in enumerate(reportData):
           if index==0:
              print(f"{row[0].ljust(metric_name_width)}    {str(row[1]).ljust(node_name_width)}    {str(row[2]).ljust(resource_name_width)} {row[3].ljust(value_width)}")
              print("-" * metric_name_width+"----"+"----"+"-" * node_name_width +"-" * resource_name_width+"----"+"-" * value_width)
           else:
              print(f"{row[0].ljust(metric_name_width)}    {str(row[1]).ljust(node_name_width)}    {str(row[2]).ljust(resource_name_width)} {row[3].ljust(value_width)}")

    else:
        print("Only support 2, 3, 4 columns")


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
            exit(1)


        print("#" * 120)
        print("Query {} data from {} to {}, time duration is {} (Min/Hour)".format(promQL,datetime.fromtimestamp(start_time),datetime.fromtimestamp(end_time),timeDuration))
        print("#" * 120)
        print()
        promQueryAPIURL = "https://"+prometheusURL+"/api/v1/query?query="
        if promQLOperation == "topMaxOverTime":
            promQL = "topk(10,max_over_time({}[{}]))".format(metricName, timeDuration)
        elif promQLOperation == "topAvgOverTime":
            promQL = "topk(10,avg_over_time({}[{}]))".format(metricName, timeDuration)
        elif promQLOperation == "topMaxOverTimeSumByPod":
            promQL = "topk(10, sum by(pod) (max_over_time({}[{}])))".format(metricName, timeDuration)
        elif promQLOperation == "topAvgOverTimeSumByPod":
            promQL = "topk(10, sum by(pod) (avg_over_time({}[{}])))".format(metricName, timeDuration)
        elif promQLOperation == "topMaxOverTimeSumByNode":
            promQL = "topk(10, sum by(node) (max_over_time({}[{}])))".format(metricName, timeDuration)
        elif promQLOperation == "topAvgOverTimeSumByNode":
            promQL = "topk(10, sum by(node) (avg_over_time({}[{}])))".format(metricName, timeDuration)
        elif promQLOperation == "getInfo" or promQLOperation == "bucket":
            promQL = "{}".format(metricName)
        elif promQLOperation == "rate":
            promQL = "topk(100,rate({}[5m]))".format(metricName)
        else:
            print("Unsupported promQL operations, support type is: topMaxOverTime,topAvgOverTime,topMaxOverTimeSumByPod,topAvgOverTimeSumByPod,topMaxOverTimeSumByNode")
            exit(1)
        print("-" * 120)
        print(promQL)
        print("-" * 120)
        requestMetricUrl=promQueryAPIURL + promQL
        #print(requestMetricUrl)


        #Disable InsecureRequestWarning: Unverified HTTPS request is being made.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        prom_metrics=requests.post(url=requestMetricUrl, headers={'Authorization': 'Bearer {}'.format(token)},verify=False).content.decode('utf8', 'ignore')
        #print()
        #print(prom_metrics)
        #print()
        prom_metrics_json=json.loads(prom_metrics)
        #print("The metrics of {} in prometheus:\n{}\n{}".format(promQL,"-" * 120,prom_metrics_json))
        #print("-" * 120)
        #print()
        reportData=[]
        if (promQLOperation == "topMaxOverTime" or promQLOperation == "topAvgOverTime") and "ovn_db_db_size_bytes" not in promQL:
        #    print("MetricName"+" " * 80+" "+"Node"+" " * 20+"ResourceName"+" " * 20+"Value")
        #    print("=" * 120)
            reportTitle=("Metric Name","Node Name","Resource Name","Value")
        elif promQLOperation == "rate" or promQLOperation == "bucket":
             if "apiserver_cache_list_total" in promQL:
                reportTitle=("Metric Name","Resource Prefix","Value")
             else:
                reportTitle=("Metric Name","Metric Group","Value")

        elif promQLOperation == "getInfo":
            if "kube_pod_status_phase" in promQL:
                reportTitle=("Metric Name","Phase","Value")
            else:
                reportTitle=("Metric Name","Value")
        else:
            reportTitle=("Metric Name","Resource Name","Value")
        #    print("MetricName"+" " * 80+" "+"ResourceName"+" " * 20+"Value")
        #    print("=" * 120)
        reportData.append(reportTitle)

        payload=generatedPayload()

        results = prom_metrics_json['data']['result']
        i=1
        for r in results:
            # print(r)

            #metricName=promQL
            nodeName=""
            metricGroup=""
            if promQLOperation == "getInfo":
               if "kube_pod_status_phase" in promQL:
                   phase=r['metric']['phase']
            elif promQLOperation == "bucket":
               if "rest_client_request_duration_seconds_bucket" in promQL:
                   metricName="rest_client_request_duration_seconds_bucket"
                   service=r['metric']['service']
                   verb=r['metric']['verb']
                   metricGroup=service+":"+verb
            elif promQLOperation == "rate":
               if "apiserver_cache_list_total" in promQL:
                  resourcePrefix=r['metric']['resource_prefix']
               elif "apiserver_request_total" in promQL:
                  resource=r['metric']['resource']
                  systemClient=r['metric']['system_client']
                  verb=r['metric']['verb']
                  returnCode=r['metric']['code']
                  metricGroup=systemClient+":"+resource+":"+verb+":"+returnCode
               elif "ovnkube_node_workqueue_adds_total" in promQL:
                  instance=r['metric']['instance']
                  podName=r['metric']['pod']
                  name=r['metric']['name']
                  metricGroup=instance+":"+podName+":"+name
               elif "ovnkube_controller_resource_update_total" in promQL:
                  instance=r['metric']['instance']
                  podName=r['metric']['pod']
                  name=r['metric']['name']
                  event=r['metric']['event']
                  metricGroup=instance+":"+podName+":"+name+":"+event
               elif "kubelet_http_requests_total" in promQL:
                  metric1=r['metric']['node']
                  metric3=r['metric']['path']
                  metric2=r['metric']['method']
                  metric4=r['metric']['server_type']
                  metricGroup=metric1+":"+metric2+":"+metric3+":"+metric4
               elif "apiserver_watch_events_total" in promQL:
                  metric1=r['metric']['instance']
                  metric2=r['metric']['kind']
                  metricGroup=metric1+":"+metric2
               elif "ovnkube_controller_workqueue_retries_total" in promQL:
                  metric1=r['metric']['instance']
                  metric2=r['metric']['pod']
                  metric3=r['metric']['name']
                  metricGroup=metric1+":"+metric2+":"+metric3
               elif "etcd_requests_total" in promQL:
                  metric1=r['metric']['instance']
                  metric3=r['metric']['operation']
                  metric2=r['metric']['type']
                  metricGroup=metric1+":"+metric2+":"+metric3
            else:
               podName=r['metric']['pod']

            if (promQLOperation == "topMaxOverTime" or promQLOperation == "topAvgOverTime") and "ovn_db_db_size_bytes" not in promQL:
               nodeName=r['metric']['node']
            # instanceName=r['metric']['instance']

            metricValue=float(r['value'][1])
            if math.isnan(metricValue):
               metricValue=float(0)
            payload["metric"]=metricName


            if promQLOperation == "getInfo":
               if "kube_pod_status_phase" in promQL:
                   payload[phase]=metricValue
               else:
                   payload["total"]=metricValue
            elif promQLOperation == "rate" or promQLOperation == "bucket":
               if "apiserver_cache_list_total" in promQL:
                   payload[resourcePrefix]=metricValue
               else:
                   payload[metricGroup]=metricValue
            else:
               payload[podName]=metricValue

            metricRow=""
            if (promQLOperation == "topMaxOverTime" or promQLOperation == "topAvgOverTime") and "ovn_db_db_size_bytes" not in promQL  :
               #print("No."+str(i)+" "+metricName+',    '+nodeName+',    '+podName+',    '+str(metricValue))
               metricRow=("No."+str(i)+" "+metricName,nodeName,podName,str(metricValue))
            elif promQLOperation == "rate" or promQLOperation == "bucket":
                if "apiserver_cache_list_total" in promQL:
                   metricRow=("No."+str(i)+" "+metricName,resourcePrefix,str(metricValue))
                else:
                   metricRow=("No."+str(i)+" "+metricName,metricGroup,str(metricValue))

            elif promQLOperation == "getInfo":
                if "kube_pod_status_phase" in promQL:
                   metricRow=("No."+str(i)+" "+metricName,phase,str(metricValue))
                elif "rest_client_request_duration_seconds_bucket" in promQL:
                   metricRow=("No."+str(i)+" "+metricName,metricGroup,str(metricValue))
                else:
                   metricRow=("No."+str(i)+" "+metricName,str(metricValue))
            else:
               #print("No."+str(i)+" "+metricName+',    '+podName+',    '+str(metricValue))
               metricRow=("No."+str(i)+" "+metricName,podName,str(metricValue))
            i +=1
            reportData.append(metricRow)

        if (promQLOperation == "topMaxOverTime" or promQLOperation == "topAvgOverTime") and "ovn_db_db_size_bytes" not in promQL:
           format_output_alligin_colums(reportData,4)
        elif promQLOperation == "rate":
              format_output_alligin_colums(reportData,3)
           #if "apiserver_cache_list_total" in promQL:
           #   format_output_alligin_colums(reportData,3)
           #else:
           #   format_output_alligin_colums(reportData,3)
        elif promQLOperation == "getInfo":
           if "kube_pod_status_phase" in promQL or "rest_client_request_duration_seconds_bucket" in promQL:
              format_output_alligin_colums(reportData,3)
           else:
              format_output_alligin_colums(reportData,2)
        else:
           format_output_alligin_colums(reportData,3)

        print()
        #print("The payload will save to elasticsearch:\n{}\n{}".format("-" * 120,payload))
        #print("-" * 120+'\n')

        payload_json = json.dumps(payload, indent=4)
        try:
           with open("ovn-metric-es-payload.json", "w") as file:
             file.write(payload_json)
        except IOError as e:
           print(f"An error occurred: {e}")

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