from pcpi import session_loader
import csv
import urllib

session_managers = session_loader.load_config()
session_man = session_managers[0]
cspm_session = session_man.create_cspm_session()

TOTAL_BRANCH_SCAN_RESULTS = {}
TOTAL_FINDINGS = []
TOTAL_POLICIES = []
TOTAL_REPOSITORIES_WITH_SECRETS = {}
TOTAL_REPOSITORIES = {}
INTEGRATED_REPOSITORIES = {}
POLICIES = {} # index of all available policies in the tenants


# TODO: dedupe 
# TODO: check for 'business contex false positives 

# Usage: 
# criteria = {
#     'key1': 'value1',
#     'key2': 'value2'
# }
# result = find_first_match(array_of_dicts, criteria)
def find_first_match(arr, criteria):
    for item in arr:
        if all(item.get(key) == value for key, value in criteria.items()):
            return item
    return None

def branch_scans():
    limit = 100
    offset = 0
    while True:
        # print(f"\n[*][*] - Fetching branch scan results @ offset {offset}")
        url = "/code/api/v2/code-issues/branch_scan"
        payload = {
            "filters": {
                "repositories": [],
                "branch": "default",
                "checkStatus": "Error",
                "codeCategories": [
                    "Secrets"
                ]
            },
            "limit": limit,
            "offset": offset,
        }
        res = cspm_session.request('POST', url, json=payload)
        if res.status_code == 200:
            result = res.json()
            data = result['data']
            nextPage = result['hasNext']
            # print(f"[*][*] - {len(data)} Branch Scans identified")
            for scan in data:
                TOTAL_BRANCH_SCAN_RESULTS[scan['resourceId']] = scan
            if not nextPage:
                break
            offset += limit

def fetch_policies():
    url = f"/v2/policy"
    
    res = cspm_session.request('GET', url)
    if res.status_code == 200:
        policies = res.json()
        print(f"Fetched {len(policies)} policies")
        for policy in policies:
            POLICIES[policy['name']] = policy
            
            
def list_repositories():
    url = "/code/api/v1/repositories"
    res = cspm_session.request('GET', url)
    if res.status_code == 200:
        repositories = res.json()
        for repo in repositories: 
            INTEGRATED_REPOSITORIES[repo['id']] = repo


def fetch_repositories_with_secrets():
    url = '/bridgecrew/api/v1/vcs-repository/repositories'
    payload = {
        "filters": {
            "issues": [
                "SECRETS"
            ]
        }
    }
    res = cspm_session.request('POST', url, json=payload)
    if res.status_code == 200:
        repositories = res.json()
        print(f"Found {len(repositories)} repositories with SECRETS issues")
        for repo in repositories:
            TOTAL_REPOSITORIES_WITH_SECRETS[repo['id']] = repo

def fetch_repositories():
    url = '/bridgecrew/api/v1/vcs-repository/repositories'
    payload = {}
    res = cspm_session.request('POST', url, json=payload)
    if res.status_code == 200:
        repositories = res.json()
        print(f"Found {len(repositories)} repositories in TOTAL")
        for repo in repositories:
            TOTAL_REPOSITORIES[repo['id']] = repo
            
def fetch_secret_policy_violations(resourceUuid):
    limit = 100
    offset = 0
    while True:
        print(f"\n[*][*] - Fetching individual repository secret policies for resourceUuid - {resourceUuid}")
        url = f'/bridgecrew/api/v2/errors/branch_scan/resources/{resourceUuid}/policies'
        payload = {
            "filters": {
                "repositories": [],
                "branch": "default",
                "checkStatus": "Error",
                "codeCategories": [
                    "Secrets"
                ]
            },
            "codeCategory": "Secrets",
            "limit": limit,
            "offset": offset,
            "sortBy": [],
            "search": {
                "scopes": [],
                "term": ""
            }
        }
        res = cspm_session.request('POST', url, json=payload)
        if res.status_code == 200:
            result = res.json()
            data = result['data']
            nextPage = result['hasNext']
            print(f"[*][*] - {len(data)} Policies identified")
            TOTAL_POLICIES.extend(data)
            if not nextPage:
                break
            offset += limit
            
def fetch_findings_per_repository():
    limit = 100
    offset = 0
    while True:
        print(f"Fetching findings with offset = {offset}")
        url = "/bridgecrew/api/v2/errors/branch_scan/resources"
        payload = {
            "filters": {
                "repositories": [],
                "branch": "default",
                "checkStatus": "Error",
                "codeCategories": [
                    "Secrets"
                ]
            },
            "offset": offset,
            "search": {
                "scopes": [],
                "term": ""
            },
            "limit": limit,
            "sortBy": [
                {
                    "key": "Severity",
                    "direction": "DESC"
                },
                {
                    "key": "Count",
                    "direction": "DESC"
                }
            ]
        }

        res = cspm_session.request('POST', url, json=payload)
        if res.status_code == 200:
            result = res.json()
            data = result['data']
            nextPage = result['hasNext']
            print(f"New findings fetched: {len(data)}")
            TOTAL_FINDINGS.extend(data)
            print(f"TOTAL FINDINGS: {len(TOTAL_FINDINGS)}")

            for finding in data:
                resourceUuid = finding['resourceUuid']
                fetch_secret_policy_violations(resourceUuid)

            if not nextPage:
                break
            offset += limit

def export_secrets_to_csv():
    filename = "secrets_report.csv"
    print(f"Creating CSV report - {filename}")
    with open(filename, 'w', newline='') as outfile:
        writer = csv.writer(outfile)

        headers = [
            'Code Category',
            'Status',
            'Severity',
            'IaC Category / Risk Factor',
            'Policy ID',
            'Policy Reference',
            'Title',
            'Custom Policy',
            'First Detection Date',
            'Last Detection Date',
            'Resource Name',
            'Org/Repo',
            # 'Suggested Fix',
            'Code Path',
            'Code Issue Line',
            'Git User',
            'Resource Code',
            'Details',
            'Repo Archived'
        ]
        writer.writerow(headers)

        # Details 
        # https://app2.prismacloud.io
        # /projects
        # ?viewId=overview
        # &checkStatus=Error
        # &repository=PCS-LAB-ORG/badCodeBom
        # &searchTerm=Grafana%20Token%20detected%20in%20code%20and%20secrets.txt

        for policy in TOTAL_POLICIES:
            details_url = f"https://app4.prismacloud.io/projects?viewId=overview&checkStatus=Error&repository={policy.get('repository', '')}&searchTerm={urllib.parse.quote(policy.get('policy',''))}"
            policy_name = policy.get('policy')
            policy_desc = POLICIES[policy_name] if policy_name in POLICIES else {}
            repo_id = policy.get('repositoryId')
            # resource_uuid = policy.get('resourceUuid')
            # criteria = {
            #     'repository': policy.get('repository'),
            #     'policy': policy.get('policy'),
            #     'codePath': policy.get('filePath')
            # }
            # branch_scan = find_first_match(TOTAL_BRANCH_SCAN_RESULTS, criteria)
            resourceId = policy['resourceId']
            branch_scan = TOTAL_BRANCH_SCAN_RESULTS[resourceId] if resourceId in TOTAL_BRANCH_SCAN_RESULTS else {}
            print(f"[*][*]FOUND A MATCHING BRANCH SCAN FOR RESOURCE_ID: {resourceId}\n\nMATCHES\n\n{branch_scan}")
            
            # branch_scan_result = TOTAL_BRANCH_SCAN_RESULTS[resource_uuid]
            repo = TOTAL_REPOSITORIES[repo_id] if repo_id in TOTAL_REPOSITORIES else {}
            integrated_repo = INTEGRATED_REPOSITORIES[repo_id]
            
            new_row = [
                branch_scan.get('codeCategory', '-'), # branch_scan
                policy.get('violationStatus', '-'), # resources
                branch_scan.get('severity', '-'), # branch_scan
                policy.get('riskFactors', '-'), # branch_scan
                policy_desc.get('policyId', 'N/A'), # policy description
                policy.get('guideline', '-'), # resources
                branch_scan.get('policy', '-'), # branch_scan
                policy.get('isCustom', '-'), # resources
                policy.get('firstDetected', '-'), # branch_scan
                integrated_repo.get('lastScanDate', '-'), # repo
                policy.get('fileName', '-'), # branch_scan
                branch_scan.get('repository', '-'), # branch_scan
                # policy_desc.get('recommendation', 'N/A'), # policy description
                branch_scan.get('codePath', '-'), # branch_scan
                branch_scan.get('codeIssueLine', '-'), # Code Issue Line ? # branch_scan
                branch_scan.get('gitUser', '-'), # resources 
                policy.get('resourceCode', '-'), # resources
                details_url,
                repo.get('isArchived', 'N/A') # repo
            ]
            writer.writerow(new_row)

def export_repositories_to_csv(filename, repositories):
    print(f"Creating CSV report - {filename}")
    with open(filename, 'w', newline='') as outfile:
        writer = csv.writer(outfile)

        headers = [
            'Name',
            'Workspace Name',
            'Full Name',
            'Url',
            'Default Branch',
            'Is Archived',
            'Has Coder Owner',
            'Is Public',
            'Privacy Level',
            'Last Updated',
            'Total Commits Count',
            'Last Commit Timestamp',
            'CI Files',
            'Contributors Count',
            'Contributors',
            'CI Instances'
        ]
        writer.writerow(headers)

        repositories = list(repositories.values())

        for repo in repositories:
            ci_files = repo.get('ciFiles', [])
            ci_files_string = ", ".join(ci_files)
            ci_instances = repo.get('ciInstances', {})
            ci_types = {key: value.get('ciType', '') for key, value in ci_instances.items()}
            pairs = [value for key, value in ci_types.items()]
            ci_string = ", ".join(pairs)
            contributors = repo.get('contributors', [])
            contributor_names = [item['name'] for item in contributors]
            contributors_string = ", ".join(contributor_names)
            
            new_row = [
                repo.get('name', '-'),
                repo.get('workspaceName', '-'),
                repo.get('fullName', '-'),
                repo.get('url', '-'),
                repo.get('defaultBranch', '-'),
                repo.get('isArchived', '-'),
                repo.get('hasCoderOwner', '-'),
                repo.get('isPublic', '-'),
                repo.get('privacyLevel', '-'),
                repo.get('lastUpdated', '-'),
                repo.get('totalCommitsCount', '-'),
                repo.get('lastCommitTimestamp', '-'),
                ci_files_string,
                repo.get('contributorsCount', '-'),
                contributors_string,
                ci_string
            ]
            writer.writerow(new_row)

fetch_policies() # mandatory
# print(POLICIES)

list_repositories()
fetch_repositories()
fetch_repositories_with_secrets()
export_repositories_to_csv("repositories_with_secrets.csv", TOTAL_REPOSITORIES_WITH_SECRETS)
export_repositories_to_csv("repositories.csv", TOTAL_REPOSITORIES)

branch_scans()
fetch_findings_per_repository() # requires fetch_repositories() or fetch_repositories_with_secrets()
# print(f"Total findings identified: {len(TOTAL_FINDINGS)}")
# print(f"Total policies identified: {len(TOTAL_POLICIES)}")
# print(f"Showing first policy: {TOTAL_POLICIES[0]}")
export_secrets_to_csv()

