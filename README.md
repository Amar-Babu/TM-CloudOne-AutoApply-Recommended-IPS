# TM-CloudOne-AutoApply-Recommended-IPS

## Description 

Using the API backend of Cloud One Workload, create a script that will run a recommendation scan on all activated workloads and apply only high or critical severity IPS rules applicable for that managed endpoint

MANDATORY variables that must be configured are as follows
| KEY  | VALUE | DEFAULT | 
| ---  | ----- | ------- | 
| configuration.api_key['api-secret-key'] | Your API Key | 'PASTE-YOUR-CLOUDONE-WORKLOAD-API-KEY-HERE' | 

Optional variables that can be configured are as follows
| KEY  | VALUE | DEFAULT | 
| ---  | ----- | ------- | 
| timeInMins | Enter the time period to filter for recently active workloads | 10 | 
| sleepTimeInMins | Enter the buffer time period to wait until completion of recommendation scan for the active workload | 15 | 
