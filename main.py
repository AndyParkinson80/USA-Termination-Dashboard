# Standard Library - Core
import os
import json
import math
import tempfile
from pathlib import Path

# Standard Library - Time/Date
import time
from datetime import datetime

# Third-party - Data Processing
import pandas as pd
import requests

# Google Cloud Platform
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from google.oauth2 import service_account
from google.cloud import secretmanager, bigquery

testing = False
data_export = True

current_folder = Path(__file__).resolve().parent
data_store = current_folder / "Data"

adp_workers = 'https://api.adp.com/hr/v2/workers'

def export_data(filename, variable):
    file_path = Path(data_store) / filename
    with open(file_path, "w") as outfile:
        json.dump(variable, outfile, indent=4)

def google_auth():
    try:
        # 1. Try Application Default Credentials (Cloud Run)
        credentials, project_id = default()
        print("✅ Authenticated with ADC")
        return credentials, project_id

    except DefaultCredentialsError:
        print("⚠️ ADC not available, trying GOOGLE_CLOUD_SECRET env var...")

        # 2. Codespaces (secret stored in env var)
        secret_json = os.getenv('GOOGLE_CLOUD_SECRET')
        if secret_json:
            service_account_info = json.loads(secret_json)
            credentials = service_account.Credentials.from_service_account_info(service_account_info)
            project_id = service_account_info.get('project_id')
            print("✅ Authenticated with service account from env var")
            return credentials, project_id

        # 3. Local dev (service account file path)
        file_path = os.getenv("GCP")
        if file_path and os.path.exists(file_path):
            credentials = service_account.Credentials.from_service_account_file(file_path)
            with open(file_path) as f:
                project_id = json.load(f).get("project_id")
            print("✅ Authenticated with service account from file")
            return credentials, project_id

        raise Exception("❌ No valid authentication method found")
    
def get_secret(secret_id, version_id="latest"):
    client = secretmanager.SecretManagerServiceClient(credentials=creds)
    name = f"projects/{project_Id}/secrets/{secret_id}/versions/{version_id}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

def load_keys(country):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"    Gathering Security Information ({now_str})")
    print(f"        Loading Security Keys ({now_str})")

    # Secrets to load
    secret_ids = {
        "client_id": f"ADP-{country}-client-id",
        "client_secret": f"ADP-{country}-client-secret",
        "country_hierarchy_USA": "country_Hierarchy_USA",
        "country_hierarchy_CAN": "country_Hierarchy_CAN",
        "strings_to_exclude": "strings_to_exclude",
        "cascade_API_id": "cascade_API_id",
        "keyfile": f"{country}_cert_key",
        "certfile": f"{country}_cert_pem",
    }

    secrets = {k: get_secret(v) for k, v in secret_ids.items()}

    return (
        secrets["client_id"],
        secrets["client_secret"],
        secrets["strings_to_exclude"],
        secrets["country_hierarchy_USA"],
        secrets["country_hierarchy_CAN"],
        secrets["cascade_API_id"],
        secrets["keyfile"],
        secrets["certfile"],
    )

def load_ssl(certfile_content, keyfile_content):
    """
    Create temporary files for the certificate and keyfile contents.
    
    Args:
        certfile_content (str): The content of the certificate file.
        keyfile_content (str): The content of the key file.
    
    Returns:
        tuple: Paths to the temporary certificate and key files.
    """
    # Create temporary files for certfile and keyfile
    temp_certfile = tempfile.NamedTemporaryFile(delete=False)
    temp_keyfile = tempfile.NamedTemporaryFile(delete=False)

    try:
        # Write the contents into the temporary files
        temp_certfile.write(certfile_content.encode('utf-8'))
        temp_keyfile.write(keyfile_content.encode('utf-8'))
        temp_certfile.close()
        temp_keyfile.close()

        return temp_certfile.name, temp_keyfile.name
    
    except Exception as e:
        # Clean up in case of error
        os.unlink(temp_certfile.name)
        os.unlink(temp_keyfile.name)
        raise e

def adp_bearer(client_id,client_secret,certfile,keyfile):
    adp_token_url = 'https://accounts.adp.com/auth/oauth/v2/token'                                                                                          

    adp_token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    adp_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    adp_token_response = requests.post(adp_token_url, cert=(certfile, keyfile), verify=True, data=adp_token_data, headers=adp_headers)

    if adp_token_response.status_code == 200:
        access_token = adp_token_response.json()['access_token']

    return access_token

def api_count_adp(page_size,url,headers,type):

    api_count_params = {
            #"$filter": "workers/workerStatus/statusCode/codeValue eq 'Terminated'",
            "count": "true",
        }
    
    api_count_response = requests.get(url, cert=(certfile, keyfile), verify=True, headers=headers, params=api_count_params) 
    response_data = api_count_response.json()
    total_number = response_data.get("meta", {}).get("totalNumber", 0)
    api_calls = math.ceil(total_number / page_size)

    return api_calls

def api_call(page_size,skip_param,api_url,api_headers,type):
    
    api_params = {
    #"$filter": "workers/workerStatus/statusCode/codeValue eq 'Terminated'",
    "$top": page_size,
    "$skip": skip_param
    }

    api_response = requests.get(api_url,cert=(certfile, keyfile), headers = api_headers, params = api_params)
    time.sleep(0.6)   

    return api_response    

def GET_workers_adp():
    adp_terminated = []

    print (f"       Downloading Terminated ADP Staff")  
    
    page_size = 100
    
    api_headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept':"application/json;masked=false"
        }
    
    api_calls = api_count_adp(page_size,adp_workers,api_headers,type)
    for i in range(api_calls):
        skip_param = i * page_size

        api_response = api_call(page_size,skip_param,adp_workers,api_headers,type)

        if api_response.status_code == 200:
            json_data = api_response.json()
            json_data = json_data['workers']
        
            filtered_data = [
                worker for worker in json_data 
                if worker.get('workerID', {}).get('idValue') not in strings_to_exclude
            ]
                
            adp_terminated.extend(filtered_data)
        else:
            continue

    if data_export:
        export_data("001 - ADP (Data Out - Terminated).json", adp_terminated)    

    return adp_terminated

def adp_rejig(data):
    adp_reordered = []
    cutoff = datetime(2025, 1, 1)

    for entry in data:
        person_name = entry["person"]["legalName"]["formattedName"]
        workerID = entry["workerID"]["idValue"]

        for assignment in entry.get("workAssignments", []):
            hire_str = assignment.get("hireDate")
            termination_str = assignment.get("terminationDate")
            job_title_code = assignment.get("jobCode",{}).get("codeValue","")
            job_title_long = assignment.get("jobCode",{}).get("longName","")
            job_title_short = assignment.get("jobCode",{}).get("shortName","")
            if job_title_long:
                job_title = job_title_long
            else:
                job_title = job_title_short

            status = assignment.get("assignmentStatus", {})
            reason = status.get("reasonCode", {}) or {}
            if reason:
                reason_code = reason.get("codeValue", "")
                reason_word = reason.get("shortName", "")
            else:
                reason_code = assignment["assignmentStatus"]["statusCode"]["codeValue"]
                reason_word = assignment["assignmentStatus"]["statusCode"]["shortName"]
            
            reports_to_list = assignment.get("reportsTo", {})
            if reports_to_list:
                formatted_name = reports_to_list[0].get("reportsToWorkerName", {}).get("formattedName", "")
            else:
                formatted_name = ""

            homeOrg = assignment.get("homeOrganizationalUnits",{})
            if not isinstance(homeOrg, list):
                homeOrg = []
            department_index = None
            for idx, record in enumerate(homeOrg):
                type_code = record.get("typeCode", {})
                code_value = type_code.get("codeValue", "")
                if code_value == "Department":
                    department_index = idx
                    break
            
            try:
                if homeOrg:
                    name_code = homeOrg[department_index].get("nameCode", {})
                    job_code = name_code.get("codeValue","")
                    job_name = name_code.get("shortName") or name_code.get("longName", "")
                else:
                    job_code = ""
                    job_name = ""
            except Exception:
                print (person_name)

            if not termination_str:
                continue

            try:
                termination_date = datetime.strptime(termination_str, "%Y-%m-%d")
                hire_date = datetime.strptime(hire_str, "%Y-%m-%d")
            except Exception:
                continue  

            if termination_date < cutoff:
                continue

            years = termination_date.year - hire_date.year
            months = termination_date.month - hire_date.month

            if months < 0:
                years -= 1
                months += 12

            if termination_date.day < hire_date.day:
                months -= 1
                if months < 0:
                    months += 12
                    years -= 1

            adp_reordered.append({
                "CO_CODE": "KZO",
                "NAME": person_name,
                "ASSOCIATE_ID": workerID,
                "HOME_DEPARTMENT": f"{job_code} - {job_name}",
                "JOB_TITLE": f"{job_title_code} - {job_title}",
                "HIRE_DATE": hire_str,
                "TERMINATION_DATE": termination_str,
                "REASON": f"{reason_code} - {reason_word}",
                "YEARS_OF_SERVICE": f"{years}:{months}",
                "REPORTS_TO": formatted_name,
            })

    # sort by termination date ascending
    adp_reordered = sorted(
        adp_reordered,
        key=lambda r: r["TERMINATION_DATE"]
    )
    if data_export:
        export_data("002 - ADP (Data Out - rejig).json", adp_reordered)

    return adp_reordered

def upload_to_bigquery(data, table_id):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("        Rebuilding Data Table in BigQuery (" + time_now + ")")

    # Initialize BigQuery client using default credentials
    client = bigquery.Client(
        project=project_Id,
        credentials=creds
    )
    dataset_id = "usa_termination_dashboard"

    def load_data(data, project_id, dataset_id, table_id):
        df = pd.DataFrame(data)
        df["HIRE_DATE"] = pd.to_datetime(df["HIRE_DATE"], errors="coerce").dt.date
        df["TERMINATION_DATE"] = pd.to_datetime(df["TERMINATION_DATE"], errors="coerce").dt.date

        table_ref = f"{project_id}.{dataset_id}.{table_id}"

        job = client.load_table_from_dataframe(df, table_ref)  # Load data
        job.result()  # Wait for the job to complete
        print(f"Data loaded into {table_id}")

    #delete_table_data(project, dataset_id, table_id)
    load_data(data, project_Id, dataset_id, table_id)

def deduplicate_terminations(project_id, dataset, table):
    client = bigquery.Client(project=project_id)

    source_table = f"`{project_id}.{dataset}.{table}`"
    temp_table = f"`{project_id}.{dataset}.{table}_deduped_tmp`"

    query = f"""
    -- Create temporary deduplicated table
    CREATE OR REPLACE TABLE {temp_table} AS
    SELECT * EXCEPT(row_num)
    FROM (
        SELECT *,
            ROW_NUMBER() OVER (PARTITION BY `ASSOCIATE_ID`, `TERMINATION_DATE` ORDER BY (SELECT NULL)) AS row_num
        FROM {source_table}
    )
    WHERE row_num = 1;

    -- Replace original with deduped
    CREATE OR REPLACE TABLE {source_table} AS
    SELECT *
    FROM {temp_table};

    -- Drop temp
    DROP TABLE {temp_table};
    """

    job = client.query(query)
    job.result()  # wait for completion

    print(f"Table `{project_id}.{dataset}.{table}` successfully deduplicated.")

if __name__ == "__main__":
    creds, project_Id = google_auth()
    
    def main_section(c):

        global access_token,certfile,keyfile,strings_to_exclude

        client_id, client_secret, strings_to_exclude, country_hierarchy_USA, country_hierarchy_CAN, cascade_API_id, keyfile, certfile = load_keys(c)
        certfile, keyfile = load_ssl(certfile, keyfile)
        access_token = adp_bearer(client_id,client_secret,certfile,keyfile)

        adp_terminated = GET_workers_adp()
        adp_rearranged = adp_rejig(adp_terminated)

        upload_to_bigquery(adp_rearranged, "usa_terminations")
        deduplicate_terminations(project_Id,"usa_termination_dashboard","usa_terminations")

    countries = ["usa"]
    for c in countries:
        main_section(c)