from pymongo import MongoClient
import sys
import os
import pickle
import requests
import time
import re
import csv
import logging
import subprocess
import configparser
from pprint import pprint
from bson.objectid import ObjectId
from datetime import datetime, timedelta


# Settings
config = configparser.ConfigParser()
working_dir = os.getcwd()
configuration_file = 'mystique.conf'
config.read((os.path.join(working_dir, configuration_file)))

# cuckoo
cuckoo_conf = config['Cuckoo']
cuckoo_ip = cuckoo_conf.get('ip')
cuckoo_port = cuckoo_conf.getint('api_port')
guest_machine_name = cuckoo_conf.get('guest_machine_name')

# mongo
mongo_conf = config['MongoDB']
mongodb_ip = mongo_conf.get('ip')
mongodb_port = mongo_conf.getint('port')
mongodb_dbname = mongo_conf.get('database_name')
mongodb_collection = mongo_conf.get('collection')
mongo_q = 'db.{0}.find'.format(mongodb_collection)

# files
files_section = config['files']
output_csv_file = files_section.get('output_file_path')
# known_good_mutexes = files_section.get('known_good_file')

# whitelist_file = files_section.get('known_good_file')
# whitelist_path = os.path.join(working_dir, whitelist_file)

# Adding logging
logger = logging.getLogger('mystique')
hdlr = logging.FileHandler('mystique.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)


def read_whitelist():
    """Loads the content of the whitelist, returns a dictionary with process names as keys, mutants as values"""
    whitelist_file = files_section.get('known_good_file')
    whitelist_path = os.path.join(working_dir, whitelist_file)

    with open(whitelist_path, 'rb') as mutants_file:
        # A dict of processes and their good mutexes
        known_good_mutexes = pickle.load(mutants_file)

    return known_good_mutexes


def match_whitelist(unknown_mutex, proc_good_mutexes_list):
    """Compares a mutex with a white-list of regular expressions"""
    # for every regex pattern in the whitelist of the current process
    for proc_mutex_regex in proc_good_mutexes_list:
        # Check if regex matches
        mutex_match = re.search(proc_mutex_regex, str(unknown_mutex))
        if mutex_match is not None:
            return True
    return False


def is_unknown(mutex_list, proc_good_mutexes_list, process_n):
    """
     Gets a list of mutexes that were created by a process, sends every mutex of the process to match_whitelist
     if not found in whitelist, the mutex is added to the list of suspicious of that process
    :param mutex_list: a list of mutexes, created by process_n
    :param proc_good_mutexes_list: a list of regular expressions of the mutexes in the whitelist for process_n
    :param process_n: the name of the current process
    :return: returns a filtered dictionary of processes and the unknown mutexes they created
    """
    in_known_good_mutex_list = False
    unknown_mutants_arr = []
    for unknown_mutex in mutex_list:
        # For every pattern of whitelist mutex of CURRENT PROCESS
        in_known_good_mutex_list = match_whitelist(unknown_mutex, proc_good_mutexes_list)
        # If the mutant was not identified as good
        if not in_known_good_mutex_list:
            unknown_mutants_arr.append(unknown_mutex)
    return unknown_mutants_arr


def query_good_mutexes(task_id):
    """
     receives a task id to get information from. Checks in a list of known good mutants 
     and returns mutexes that are not in there. This narrows down the amount of FPs
     returns a dictionary of unknown mutants ( {"Process_name":[list of unknown mutants for this process]} )
    """
    suspicious_mutexes = {}
    known_good_mutexes = read_whitelist()
    # From the task report - process & their mutants (if they have any)
    report_mutant_process = db[mongodb_collection].find({'info.id': task_id},
                            {'behavior.generic.summary.mutex': 1, 'behavior.generic.process_name': 1})
    try:
        # Get all mutexes from the report and their owners.
        analysis_behavior_data = report_mutant_process[0]["behavior"]["generic"]
        for behavior_item in analysis_behavior_data:
            if "mutex" in behavior_item["summary"]:
                temp_mutexes = behavior_item["summary"]["mutex"]
                process_n = behavior_item["process_name"]
                # Checks if the process name is in the whitelist, checks if the mutexes are in the process' whitelist
                if str(process_n) in known_good_mutexes.keys():
                    suspicious_mutexes[process_n] = is_unknown(temp_mutexes, known_good_mutexes[process_n], process_n)

                else:
                    # Process name IS NOT in whitelist, all of its mutexes are considered as suspicious
                    suspicious_mutexes[process_n] = is_unknown(temp_mutexes, known_good_mutexes['general'], process_n)

    except Exception as ex:
        logger.error(ex)
        pass

    return suspicious_mutexes


def submit_sample(sample_path, guest_machine):
    """
    Submits a sample to cuckoo.
    :param sample_path: full path of the sample on disk 
    :param guest_machine: exact name of the machine to analyse the sample
    :return: task ID of the analysed sample 
    """
    with open(sample_path, "rb") as sample:
        sample_name = sample_path.replace("\\", "_")
        files = {"file": (sample_name, sample)}
        data = {"machine": guest_machine}
        r = requests.post(REST_URL, files=files, data=data)
        logger.info("Posted file to analyze...")
        return r.json()["task_id"]


def wait_for_analysis_report(task_id):
    """ queries the status of the task, waiting until it is reported - 
    otherwise following functions can not operate, they depened on the results of the report"""
    view_task = 'http://{0}:{1}/tasks/view/{2}'.format(cuckoo_ip, cuckoo_port, task_id)
    all_task_info = requests.get(view_task).json()
    # as long as the sample is not in "reported" status, keep sleeping
    while all_task_info["task"]["status"] == "running" \
            or all_task_info["task"]["status"] == "pending" \
            or all_task_info["task"]["status"] == "completed":
        all_task_info = requests.get(view_task).json()
        logger.info('Task {0} is working...'.format(task_id))
        time.sleep(35)


def is_reported(task_id):
    view_task = 'http://{0}:{1}/tasks/view/{2}'.format(cuckoo_ip, cuckoo_port, task_id)
    all_task_info = requests.get(view_task).json()
    if all_task_info["task"]["status"] == "reported":
        logger.info("task completed.")
        logger.info('Started on: {0}, Completed on: {1}'
                    .format(all_task_info["task"]["started_on"], all_task_info["task"]["completed_on"]))
    else:
        logger.error("Task not reported yet - Something went wrong...")


def write_results(results_dictionary, output_csv):
    file_exists = os.path.isfile(output_csv)
    with open(output_csv, 'a') as results_output_file:
        w = csv.DictWriter(results_output_file, fieldnames=results_dictionary.keys())
        if not file_exists:
            w.writeheader()
        w.writerow(results_dictionary)


def query_task_behavior(task_id):
    try:
        current_tree = db[mongodb_collection].find({"info.id": task_id}, {"behavior.processes": 1})
        current_process_tree = current_tree[0]["behavior"]["processes"]
    except:
        current_process_tree = []
    return current_process_tree


def query_dropped_files(task_id):
    try:
        current_dropped = db[mongodb_collection].find({"info.id": task_id}, {"dropped": 1})
        current_dropped_files = current_dropped[0]["dropped"]
    except:
        current_dropped_files = []
    return current_dropped_files


def return_bad_mutexes(task_id, first_id, curr_mutex, proc_name, file_path, output_csv):
    """
    Opens the reports and returns only the mutants that seem to stop the process from executing
    :param task_id: id of the current task
    :param first_id: id of the original task
    :param curr_mutex: current mutant that is being checked 
    :param proc_name: name of the process that created this mutant
    :param file_path: full path of the sample
    :param output_csv: path to output  
    :return: prints output to csv file
    """
    first_task = 'http://{0}:{1}/tasks/view/{2}'.format(cuckoo_ip, cuckoo_port, first_id)
    first_task_info = requests.get(first_task).json()
    following_task = 'http://{0}:{1}/tasks/view/{2}'.format(cuckoo_ip, cuckoo_port, task_id)
    following_task_info = requests.get(following_task).json()
    # query behavior results from tasks
    first_process_tree = query_task_behavior(first_id)
    current_process_tree = query_task_behavior(task_id)
    first_dropped_files = query_dropped_files(first_id)
    current_dropped_files = query_dropped_files(task_id)

    if first_task_info["task"]["status"] == "reported":
        first_analysis_duration = first_task_info['task']['duration']
        following_analysis_duration = following_task_info['task']['duration']
        # Checks if analysis time shortened
        if following_analysis_duration < first_analysis_duration:
            # query virustotal on this mutant
            rep_res = query_mutex_vt(curr_mutex.replace("\\", "\\\\"))
            logger.info('The mutex: {0} \tcreated by: {1} \n'
                        'shortened analysis time from {2} to {3}. Bad/Good detection: {4}/{5})'
                        .format(curr_mutex, proc_name, first_analysis_duration, following_analysis_duration,
                        rep_res[0], rep_res[1]))
            delta = first_analysis_duration - following_analysis_duration
            result = {"Mutex_name": curr_mutex,
                      "First_analysis_duration": first_analysis_duration,
                      "Curr_analysis_duration": following_analysis_duration,
                      "Delta": delta,
                      "VT_Bad_detection": rep_res[0],
                      "VT_Good_detection": rep_res[1],
                      "File": file_path,
                      "Process name": proc_name,
                      "First_Process_Tree": len(first_process_tree),
                      "Following_Process_Tree": len(current_process_tree),
                      "First_Dropped_Files": len(first_dropped_files),
                      "Current_Dropped_Files": len(current_dropped_files)
                      }
            write_results(result, output_csv)
    else:
        print "Something went wrong...\n"


def perform_vt_query(q):
    """
    :param q: VT query as string
    :return: Array of hashes matching the query q
    """
    try:
        logger.info("performing query:\n" + q)
        params = {'apikey': api_key,
                  'query': q}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params=params)
        response_json = response.json()
        result_hashes = response_json["hashes"]
        logger.info("Query completed.\n")
        return result_hashes
    except Exception, e:
        logger.error(e)


def query_mutex_vt(query_mutex):
    """
    Submits a query to VT to see if the mutex exists in their behavioral report
    :param query_mutex: a mutex to be queried in VT behavioural reports
    :return: returns reputation of the queried mutant
    """
    a_week_ago = datetime.now() - timedelta(days=7)
    day = str(a_week_ago.day)
    if len(day) == 1:
        day = "0" + day
    month = str(a_week_ago.month)
    if len(month) == 1:
        month = "0" + month
    year = str(a_week_ago.year)
    computed_date = year + "-" + month + "-" + day + "T00:00:01+ "

    # selects "bad" as samples with detection rate of 20 or more
    suspected_2b_bad = "not((engines:\"pua\") or (engines:\"pup\") " \
                       "or (engines:\"adware\") or (engines:\"toolbar\")" \
                       "or (engines:\"riskware\")) " \
                       "type:peexe positives:20+ behaviour:\"" + query_mutex + "\" " \
                        "la:" + computed_date + \
                       "size:10MB-"
    # selects "good" as samples with detection rate of 2 or less
    suspected_2b_good = "not((engines:\"pua\") or (engines:\"pup\") or (engines:\"adware\") " \
                        "or (engines:\"toolbar\")or (engines:\"riskware\")) " \
                        "type:peexe positives:2- behaviour:\"" + query_mutex + "\" " \
                        "la:" + computed_date + \
                        "size:10MB-"
    hashes_b = perform_vt_query(suspected_2b_bad)
    hashes_g = perform_vt_query(suspected_2b_good)
    reputation_results = []
    try:
        reputation_results.append(len(hashes_b))
    except:
        reputation_results.append(0)
    try:
        reputation_results.append(len(hashes_g))
    except:
        reputation_results.append(0)

    return reputation_results

def submit_sample_with_mutant(REST_URL, SAMPLE_FILE, mutant, guest_machine):
    """
    Submits a sample to cuckoo, this time using the package "mutex". 
    The package receives a mutant to create on the guest machine.
    :param REST_URL: to create submission task
    :param SAMPLE_FILE: full path of the file to analyse 
    :param mutant: A mutant that will be created on the guest machine before the sample will be executed
    :param guest_machine: exact name of the cuckoo guest machine that will analyse the sample 
    :return: returns id of the current task
    """
    with open(SAMPLE_FILE, "rb") as sample:
        files = {"file": ("sample_checkout_mutexes", sample)}
        data = {"machine": guest_machine, "package": "mutex",
                "options": "mutexes=" + mutant}
        r = requests.post(REST_URL, files=files, data=data)
        logger.info("Uploaded task to analyze again: with package mutex")
        task_id = r.json()["task_id"]
        logger.info('Task Created: '.format(task_id))
        return task_id


def main(SAMPLE_FILE):
    # Connecting to mongoDB to query it for results
    client = MongoClient(mongodb_ip, mongodb_port)
    global db
    global analysis
    # Name of the database
    db = client[mongodb_dbname]
    # Name of the collection
    analysis = db[mongodb_collection]
    global api_key
    api_key = config['virustotal'].get('api_key')
    logger.info("Connected to DB...")

    # Submitting file to analysis
    global REST_URL
    # REST api to create new tasks
    REST_URL = 'http://{0}:{1}/tasks/create/file'.format(cuckoo_ip, cuckoo_port)
    # Submitting the sample to cuckoo, receiving back it's task ID
    first_id = submit_sample(SAMPLE_FILE, guest_machine_name)
    logger.info('{0} : First time sample is running. Current task id is {1}'.format(SAMPLE_FILE, first_id))
    # waiting for analysis to stop running
    wait_for_analysis_report(first_id)
    # Check that indeed a report was created, otherwise it won't work
    is_reported(first_id)
    # Filtering out known-good mutants
    mutexes_to_check = query_good_mutexes(first_id)
    logger.info(mutexes_to_check)
    if mutexes_to_check is not None:
        for index, mutex in enumerate(mutexes_to_check):
            for checking in mutexes_to_check.values()[index]:
                logger.info("Testing mutex: " + checking)
                # Submit the same sample, with different mutant
                curr_task_id = submit_sample_with_mutant(REST_URL, SAMPLE_FILE, checking, guest_machine_name)
                # Suspend script until the task is reported and has results
                wait_for_analysis_report(curr_task_id)
                is_reported(curr_task_id)
                # Returns if this mutant can vaccinate against the sample
                return_bad_mutexes(curr_task_id, first_id, checking, mutex, SAMPLE_FILE, output_csv_file)
    logger.info('Finished examining all mutants for {0}. Check the output csv file.'.format(SAMPLE_FILE))

if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception as e:
        print(e)