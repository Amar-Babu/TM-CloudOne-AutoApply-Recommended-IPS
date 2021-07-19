from __future__ import print_function
import sys, warnings
import deepsecurity
import time
from deepsecurity.rest import ApiException
from deepsecurity.models.firewall_computer_extension import FirewallComputerExtension
from pprint import pprint

'''

Task Description : Using the API backend of Cloud One Workload, create a script that will run a recommendation scan on all activated workloads and apply only high or critical severity IPS rules applicable for that system


1) Create client
2) Get all activated workloads , store in list 
        https://cloudone.trendmicro.com/docs/workload-security/api-reference/tag/Computers
    List Computers, store IDs in list (Introduce commmentable overdrive list here )
3) Run a recommendation scan
    https://cloudone.trendmicro.com/docs/workload-security/api-reference/tag/Scheduled-Tasks#operation/createScheduledTask
    RunNow, scan-for-recommendations, computeID filter
    Create a scheduled task , store ID 
    https://cloudone.trendmicro.com/docs/workload-security/api-reference/tag/Scheduled-Tasks#operation/listScheduledTasks
    # Reuse the scheduled task, same ID 
4) Get all IPS , with high or critical severity and store ruleIDs in list 
    https://cloudone.trendmicro.com/docs/workload-security/api-reference/tag/Intrusion-Prevention-Rules#operation/createIntrusionPreventionRule
    Search Intrusion Prevention Rules
5) Computer Intrusion Prevention Assignments 
    https://cloudone.trendmicro.com/docs/workload-security/api-reference/tag/Computer-Intrusion-Prevention-Rule-Assignments-and-Recommendations
    Set IPS ruleList 

'''

#Configuration 
timeInMins = 10 
sleepTimeInMins = 10

# Setup
if not sys.warnoptions:
	warnings.simplefilter("ignore")
configuration = deepsecurity.Configuration()
configuration.host = 'https://cloudone.trendmicro.com/api'

# Authentication
configuration.api_key['api-secret-key'] = 'PASTE-YOUR-CLOUDONE-WORKLOAD-API-KEY-HERE'

# Version
api_version = 'v1'

# Initialization
# Set Any Required Values
#FirewallRulesApi = deepsecurity.FirewallRulesApi(deepsecurity.ApiClient(configuration))
#ComputerFirewallRuleAssignmentsApi = deepsecurity.ComputerFirewallRuleAssignmentsApi(deepsecurity.ApiClient(configuration))
ComputersApi = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
ScheduledTasksApi = deepsecurity.ScheduledTasksApi(deepsecurity.ApiClient(configuration))
IntrusionPreventionRulesApi = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(configuration))
ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi = deepsecurity.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi(deepsecurity.ApiClient(configuration))

overrides = False

cm_search_filter = deepsecurity.SearchFilter()
expand_options = deepsecurity.Expand()
expand_options.add(expand_options.none)
expand = expand_options.list()

#Methods

# Get the scheduledTask ID, create if not already found in the system
def getFirstScheduledTaskWithNameValue(string_value):
    scheduledTaskSearch = deepsecurity.SearchCriteria(field_name = 'name',string_value = string_value)
    search_criteria_list = [scheduledTaskSearch]
    search_filter = deepsecurity.SearchFilter(search_criteria = search_criteria_list)
    st_query_resultList = ScheduledTasksApi.search_scheduled_tasks(api_version, search_filter=search_filter).scheduled_tasks
    if len(st_query_resultList) > 0 :
        return st_query_resultList[0]
    elif 'Custom-ScheduledTask-SendPolicy-Now-' in string_value:
        print('Scheduled task '+ string_value + ' not found, creating a new task')
        computerFilter = deepsecurity.ComputerFilter(type='computer',computer_id = getValidComputerID())
        sendPolicyTaskParameters = deepsecurity.SendPolicyTaskParameters(computer_filter = computerFilter)
        onceOnlyScheduleParameters = deepsecurity.OnceOnlyScheduleParameters(start_time=getPreviousEpochTime(10))
        scheduleDetails = deepsecurity.ScheduleDetails(recurrence_type= 'none', time_zone = 'US/Eastern',once_only_schedule_parameters = onceOnlyScheduleParameters)
        scheduled_task = deepsecurity.ScheduledTask(name=string_value, enabled = False, send_policy_task_parameters= sendPolicyTaskParameters,type = 'send-policy',schedule_details = scheduleDetails)
        api_response = ScheduledTasksApi.create_scheduled_task(scheduled_task, api_version)
        return api_response
    elif 'Custom-ScheduledTask-RecommendationScan-Now-' in string_value:
        print('Scheduled task '+ string_value + ' not found, creating a new task')
        computerFilter = deepsecurity.ComputerFilter(type='computer',computer_id = getValidComputerID())
        scanForRecommendationsTaskParameters = deepsecurity.ScanForRecommendationsTaskParameters(computer_filter = computerFilter)
        onceOnlyScheduleParameters = deepsecurity.OnceOnlyScheduleParameters(start_time=getPreviousEpochTime(10))
        scheduleDetails = deepsecurity.ScheduleDetails(recurrence_type= 'none', time_zone = 'US/Eastern',once_only_schedule_parameters = onceOnlyScheduleParameters)
        scheduled_task = deepsecurity.ScheduledTask(name=string_value, enabled = False, scan_for_recommendations_task_parameters= scanForRecommendationsTaskParameters,type = 'scan-for-recommendations',schedule_details = scheduleDetails)
        api_response = ScheduledTasksApi.create_scheduled_task(scheduled_task, api_version)
        return api_response
    return 0

def pushPolicyToComputer(computer_id):
    refreshPolicySchedTaskName= 'Custom-ScheduledTask-SendPolicy-Now-' + str(computer_id)
    refreshPolicySchedTask = getFirstScheduledTaskWithNameValue(refreshPolicySchedTaskName)
    refreshPolicySchedTask._enabled = True
    refreshPolicySchedTask._run_now = True
    refreshPolicySchedTask._send_policy_task_parameters._computer_filter._computer_id = computer_id
    response = ScheduledTasksApi.modify_scheduled_task(refreshPolicySchedTask._id, refreshPolicySchedTask, api_version)
    print("Policy settings pushed to ", computer_id)
    return 

def runRecommendationScanNowOnComputer(computer_id):
    recommendationScanTaskName = 'Custom-ScheduledTask-RecommendationScan-Now-' + str(computer_id)
    rcScanPolicySchedTask = getFirstScheduledTaskWithNameValue(recommendationScanTaskName)
    rcScanPolicySchedTask._enabled = True
    rcScanPolicySchedTask._run_now = True
    rcScanPolicySchedTask._scan_for_recommendations_task_parameters._computer_filter._computer_id = computer_id
    response = ScheduledTasksApi.modify_scheduled_task(rcScanPolicySchedTask._id, rcScanPolicySchedTask, api_version)
    print("Triggering Recommendation Scan on ", computer_id)
    return 

def getIntrusionPreventionRulesWithSeverity(severity):
    allowed_values = ["low", "medium", "high", "critical"]
    if severity not in allowed_values:
            raise ValueError(
                "Invalid value for `severity` ({0}), must be one of {1}" 
                .format(severity, allowed_values)
            )
    IPSevSearch = deepsecurity.SearchCriteria(field_name = 'severity',choice_test= 'equal', choice_value= severity)
    IPRuleList = IntrusionPreventionRulesApi.search_intrusion_prevention_rules(api_version, search_filter=deepsecurity.SearchFilter(search_criteria = [IPSevSearch]))._intrusion_prevention_rules
    return IPRuleList

def extractIPRuleIDsfromIPRList(IPRuleList):
    RuleIDList = []
    for IPRule in IPRuleList:
        RuleIDList.append(IPRule._id)
    return RuleIDList

def getPreviousEpochTime(timeBufferInMins):
    previousEpochTimeInMillisecs = int((time.time() - 60*timeBufferInMins)*1000)
    return previousEpochTimeInMillisecs

def getComputersLastActiveInEpochTime(epochTimeInMillisecs):
    computerSearchRecentActive = deepsecurity.SearchCriteria(field_name = 'lastAgentCommunication',first_date_value=  epochTimeInMillisecs, first_date_inclusive= True)
    search_criteria_list = [computerSearchRecentActive]
    api_response = ComputersApi.search_computers(api_version, search_filter=deepsecurity.SearchFilter(search_criteria = search_criteria_list), expand=expand, overrides=overrides)
    recentlyActiveHostIDList = []
    for computer in api_response.computers:
        recentlyActiveHostIDList.append(computer.id)
    return recentlyActiveHostIDList

def getAssignedIPRuleList(host_ID):
    expand_options = deepsecurity.Expand()
    expand_options.add(expand_options.intrusion_prevention)
    expand = expand_options.list()
    computer = ComputersApi.describe_computer(computer_id = host_ID, api_version = api_version, expand=expand, overrides=overrides)
    intrusion_prevention_config = computer._intrusion_prevention
    if(intrusion_prevention_config._rule_ids is not None):
        return intrusion_prevention_config._rule_ids
    return []

def getValidComputerID():
    api_response = ComputersApi.search_computers(api_version, search_filter=deepsecurity.SearchFilter(), expand=expand, overrides=overrides)
    return api_response.computers[-1].id

def recommendationScanAutoImplementOn(host_ID):		
    api_response = ComputersApi.modify_computer_setting(host_ID, 'intrusion_prevention_setting_auto_apply_recommendations_enabled', deepsecurity.SettingValue('Yes'), api_version, overrides=overrides)
    return

#MainLogic
try:
    successfullyUpdatedHostIDList = []
    # Get list of workloads active in the last $
    recentlyActiveHostIDList = getComputersLastActiveInEpochTime(getPreviousEpochTime(timeInMins))
    print(" Active workloads : ", recentlyActiveHostIDList)

    # Comment out the following part to enable changes to cover scope to all computers
    #recentlyActiveHostIDList = [4000] 
    
    intrusion_prevention_on_config = deepsecurity.IntrusionPreventionComputerExtension(state = 'prevent', rule_ids = [])

    for activeWorkloadID in recentlyActiveHostIDList:
    
        # Switch ON IPS module on the endpoint/compute instance
        expand_options = deepsecurity.Expand()
        expand_options.add(expand_options.intrusion_prevention)
        expand = expand_options.list()
        computer = deepsecurity.Computer(intrusion_prevention=intrusion_prevention_on_config)
        api_response = ComputersApi.modify_computer(activeWorkloadID, computer, api_version, expand=expand, overrides=overrides)

        # Switch ON auto implement for recommendations
        recommendationScanAutoImplementOn(activeWorkloadID)

        # Schedule task for Recommendation Scan
        runRecommendationScanNowOnComputer(activeWorkloadID)
        print(" Recommendation Scan trigger request passed to ", activeWorkloadID)
        pushPolicyToComputer(activeWorkloadID)
        print(" Send Policy triggered for ", activeWorkloadID)
        print(" ------------------------- ")
    
    for i in range(sleepTimeInMins,0,-1):
        time.sleep(60*1) # Sleep for 1 minutes
        print("SleepTime left "+ str(i) + " mins")
    
    print(" ------------------------- ")

    highSevIPList = getIntrusionPreventionRulesWithSeverity('high')
    criticalSevIPList = getIntrusionPreventionRulesWithSeverity('critical')
    # Merge the results
    highSevIPList.extend(criticalSevIPList)
    print(" Total High & Critical IPRules found : ",len(highSevIPList))


    highCriticalIPRuleIDList = extractIPRuleIDsfromIPRList(highSevIPList)



    for activeWorkloadID in recentlyActiveHostIDList:

        recommendedIPRuleList = getAssignedIPRuleList(activeWorkloadID)
        print("Recommended : "+ str(recommendedIPRuleList))
        if(len(recommendedIPRuleList) > 0):

            # Use the following line if you want to set/override the IP Rules 
            #IPRuleList = highCriticalIPRuleIDList

            # Use the following line if you want to append the IP Rules 
            IPRuleList = list(set(recommendedIPRuleList) & set(highCriticalIPRuleIDList)) 
            print(IPRuleList)
            intrusion_prevention_config = deepsecurity.IntrusionPreventionComputerExtension(state = 'prevent', rule_ids = IPRuleList)

            # Enforce IPS rules isolation to the endpoint/compute instance
            expand_options = deepsecurity.Expand()
            expand_options.add(expand_options.intrusion_prevention)
            expand = expand_options.list()
            computer = deepsecurity.Computer(intrusion_prevention=intrusion_prevention_config)
            api_response = ComputersApi.modify_computer(activeWorkloadID, computer, api_version, expand=expand, overrides=overrides)

            print(" Isolation Prevention rules pushed to ", activeWorkloadID)
            pushPolicyToComputer(activeWorkloadID)
            print(" Send Policy triggered for ", activeWorkloadID)
            print(" ************************ ")
            
            successfullyUpdatedHostIDList.append(activeWorkloadID)
            print("Host "+str(activeWorkloadID) + " has  been updated ! ")
        else:
            print("Host "+str(activeWorkloadID) + " has not been updated")
        
        
       
    print("Target endpoints : "+ str(recentlyActiveHostIDList))
    print("Successful Update on endpoints : "+ str(successfullyUpdatedHostIDList))

    raise SystemExit("Closing the system")
    
except ApiException as e:
	print("An exception occurred when calling API : %s\n" % e)

