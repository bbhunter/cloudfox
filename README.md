# :fox_face: CloudFox :fox_face:
CloudFox helps you gain situational awareness in unfamiliar cloud environments. It’s an open source command line tool created to help penetration testers and other offensive security professionals find exploitable attack paths in cloud infrastructure. 

> **CLOUDFOX UPDATE REQUIRED: (12/2025):** If you are using `cloudfox`, you need to use v1.17.0 or greater. All earlier versions [stopped working after a format change in AWS's public service mapping file](https://github.com/BishopFox/cloudfox/pull/109). 

**Overview** 

#### CloudFox helps you answer the following common questions (and many more): 

* What regions is this AWS account using and roughly how many resources are in the account?
* What secrets are lurking in EC2 userdata or service specific environment variables?
* What workloads have administrative permissions attached?  
* What actions/permissions does this [principal] have?
* What role trusts are overly permissive or allow cross-account assumption?
* What endpoints/hostnames/IPs can I attack from an external starting point (public internet)?
* What endpoints/hostnames/IPs can I attack from an internal starting point (assumed breach within the VPC)?
* What filesystems can I potentially mount from a compromised resource inside the VPC?

## Demos, Examples, Walkthroughs
* [Blog - Introducing: CloudFox](https://bishopfox.com/blog/introducing-cloudfox)
* [Video - CloudFox + CloudFoxable A Powerful Duo for Mastering the Art of Identifying and Exploiting AWS Attack Paths](https://www.youtube.com/watch?v=RdQiIvCrSzk)
* [Video - Penetration Testing with CloudFox](https://www.youtube.com/watch?v=Ljt_JUp5HbM)
* [Video - CloudFox Intro Demos](https://www.youtube.com/watch?v=ReWoUgpUuiQ)
* [Video - Tool Talk: CloudFox AWS sub-command walkthroughs](https://youtu.be/KKsYfL5uVU4?t=360)

## Intentionally Vulnerable Playground 
* [CloudFoxable - A Gamified Cloud Hacking Sandbox](https://cloudfoxable.bishopfox.com/)

## Want to chat about CloudFox? 
Join us on the [RedSec discord server](https://discord.gg/redsec)


## Quick Start
CloudFox is modular (you can run one command at a time), but there is an `aws all-checks` command that will run the other aws commands for you with sane defaults: 

`cloudfox aws --profile [profile-name] all-checks`

![](/.github/images/cloudfox-output-p1.png)
![](/.github/images/cloudfox-output-p2.png)

### White Box Enumeration
CloudFox was designed to be executed by a principal with limited read-only permissions, but it's purpose is to help you find attack paths that can be exploited in simulated compromise scenarios (aka, objective based penetration testing). 

### Black Box Enumeration 
CloudFox can be used with "found" credentials, similar to how you would use [weirdAAL](https://github.com/carnal0wnage/weirdAAL) or [enumerate-iam](https://github.com/andresriancho/enumerate-iam). Checks that fail, do so silently, so any data returned means your "found" creds have the access needed to retrieve it.   

### Documentation
For the full documentation please refer to our [wiki](https://github.com/BishopFox/CloudFox/wiki).


## Supported Cloud Providers

| Provider| CloudFox Commands |
| - | - |
| AWS | 34 |
| Azure | 4 |
| GCP | 58 |
| Kubernetes | Support Planned | 


# Install

**Option 1:** Download the [latest binary release](https://github.com/BishopFox/cloudfox/releases) for your platform.

**Option 2:** If you use homebrew: `brew install cloudfox`

**Option 3:** [Install Go](https://golang.org/doc/install), use `go install github.com/BishopFox/cloudfox@latest` to install from the remote source
 
**Option 4:** Developer mode:

   [Install Go](https://golang.org/doc/install), clone the CloudFox repository and compile from source
   ```
   # git clone https://github.com/BishopFox/cloudfox.git
   # cd ./cloudfox
   # Make any changes necessary
   # go build .
   # ./cloudfox
   ```

**Option 5:** Testing a bug fix
  ```
  git clone git@github.com:BishopFox/cloudfox.git
  git checkout seth-dev 
  go build .
  ./cloudfox [rest of the command options]
  ```

# Prerequisites


### AWS
* AWS CLI installed
* Supports AWS profiles, AWS environment variables, or metadata retrieval (on an ec2 instance)
   * To run commands on multiple profiles at once, you can specify the path to a file with a list of profile names separated by a new line using the `-l` flag or pass all stored profiles with the `-a` flag.
* A principal with one recommended policies attached (described below)
* Recommended attached policies: **`SecurityAudit` + [CloudFox custom policy](./misc/aws/cloudfox-policy.json)** 

Additional policy notes (as of 09/2022):    

| Policy | Notes | 
| - | - |
| [CloudFox custom policy](./misc/aws/cloudfox-policy.json) | Has a complete list of every permission cloudfox uses and nothing else |
|  `arn:aws:iam::aws:policy/SecurityAudit` | Covers most cloudfox checks but is missing newer services or permissions like apprunner:\*, grafana:\*, lambda:GetFunctionURL, lightsail:GetContainerServices |
|  `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` | Covers most cloudfox checks but is missing newer services or permissions like AppRunner:\*, grafana:\*, lambda:GetFunctionURL, lightsail:GetContainerServices - and is also missing iam:SimulatePrincipalPolicy. 
|  `arn:aws:iam::aws:policy/ReadOnlyAccess` | Only missing AppRunner, but also grants things like "s3:Get*" which can be overly permissive. |
|  `arn:aws:iam::aws:policy/AdministratorAccess` | This will work just fine with CloudFox, but if you were handed this level of access as a penetration tester, that should probably be a finding in itself :) |

### Azure
* Viewer or similar permissions applied. 

# AWS Commands
| Provider | Command Name | Description 
| - | - | - | 
| AWS | [all-checks](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#all-checks) | Run all of the other commands using reasonable defaults. You'll  still want to check out the non-default options of each command, but this is a great place to start.  |
| AWS | [access-keys](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#access-keys) | Lists active access keys for all users. Useful for cross referencing a key you found with which in-scope account it belongs to.  |
| AWS | [api-gw](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#api-gw) | Lists API gateway endpoints and gives you custom curl commands including API tokens if they are stored in metadata. |
| AWS | [buckets](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#filesystems)  | Lists the buckets in the account and gives you handy commands for inspecting them further.  |
| AWS | [cape](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#cape)  |  Enumerates cross-account privilege escalation paths. Requires `pmapper` to be run first |
| AWS | [cloudformation](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#cloudformation)  | Lists the cloudformation stacks in the account. Generates loot file with stack details, stack parameters, and stack output - look for secrets. |
| AWS | [codebuild](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#codebuild)  | Enumerate CodeBuild projects |
| AWS | [databases](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#databases)  | Enumerate RDS databases. Get a loot file with connection strings. |
| AWS | [ecr](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#ecr) | List the most recently pushed image URI from all repositories. Use the loot file to pull selected images down with docker/nerdctl for inspection. |
| AWS | [ecs-tasks](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#ecs-tasks) | List all ecs tasks. This returns a list of ecs tasks and associated cluster, task definition, container instance, launch type, and associated IAM principal. |
| AWS | [eks](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#eks) | List all EKS clusters, see if they expose their endpoint publicly, and check the associated IAM roles attached to reach cluster or node group. Generates a loot file with the `aws eks udpate-kubeconfig` command needed to connect to each cluster. |
| AWS | [elastic-network-interfaces](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#eni) | List all eni information. This returns a list of eni ID, type, external IP, private IP, VPCID, attached instance and a description. |
| AWS | [endpoints](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#endpoints) | Enumerates endpoints from various services. Scan these endpoints from both an internal and external position to look for things that don't require authentication, are misconfigured, etc. |
| AWS | [env-vars](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#env-vars) | Grabs the environment variables from services that have them (App Runner, ECS, Lambda, Lightsail containers, Sagemaker are supported. If you find a sensitive secret, use `cloudfox iam-simulator` AND `pmapper` to see who has access to them. |
| AWS | [filesystems](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#filesystems)  |  Enumerate the EFS and FSx filesystems that you might be able to mount without creds (if you have the right network access). For example, this is useful when you have `ec:RunInstance` but not `iam:PassRole`.  |
| AWS | [iam-simulator](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#iam-simulator) | Like pmapper, but uses the IAM policy simulator. It uses AWS's evaluation logic, but notably, it doesn't consider transitive access via privesc, which is why you should also always also use pmapper.   |
| AWS | [instances](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#instances) | Enumerates useful information for EC2 Instances in all regions like name, public/private IPs, and instance profiles. Generates loot files you can feed to nmap and other tools for service enumeration.  |
| AWS | [inventory](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#inventory) | Gain a rough understanding of size of the account and preferred regions.  |
| AWS | [lambda](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#lambda)  | Lists the lambda functions in the account, including which one's have admin roles attached. Also gives you handy commands for downloading each function.  |
| AWS | [network-ports](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#network-ports) | Enumerates AWS services that are potentially exposing a network service. The security groups and the network ACLs are parsed for each resource to determine what ports are potentially exposed. |
| AWS | [orgs](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#orgs)  |  Enumerate accounts in an organization |
| AWS | [outbound-assumed-roles](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#outbound-assumed-roles)  |  List the roles that have been assumed by principals in this account. This is an excellent way to find outbound attack paths that lead into other accounts. |
| AWS | [permissions](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#permissions) | Enumerates IAM permissions associated with all users and roles. Grep this output to figure out what permissions a particular principal has rather than logging into the AWS console and painstakingly expanding each policy attached to the principal you are investigating. |
| AWS | [pmapper](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#pmapper) | Looks for pmapper data stored on the local filesystem, [in the locations defined here](https://github.com/nccgroup/PMapper/wiki/Frequently-Asked-Questions#where-does-pmapper-store-its-data). If pmapper data has been found (you already ran `pmapper graph create`), then this command will use this data to build a graph in cloudfox memory let you know who can privesc to admin. 
| AWS | [principals](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#principals) | Enumerates IAM users and Roles so you have the data at your fingertips. |
| AWS | [ram](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#ram) | List all resources in this account that are shared with other accounts, or resources from other accounts that are shared with this account. Useful for cross-account attack paths. |
| AWS | [resource-trusts](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#resource-trusts) | Looks through multiple services that support resource policies and helps you find any overly permissive resource trusts. KMS is supported but disabled by default. To include KMS resource policies in the output, add this flag to the command: `cloudfox aws resource-trusts --include-kms`.|
| AWS | [role-trusts](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#role-trusts) | Enumerates IAM role trust policies so you can look for overly permissive role trusts or find roles that trust a specific service. |
| AWS | [route53](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#route53) | Enumerate all records from all route53 managed zones. Use this for application and service enumeration. |
| AWS | [secrets](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#secrets) | List secrets from SecretsManager and SSM. Look for interesting secrets in the list and then see who has access to them using use `cloudfox iam-simulator` and/or `pmapper`. |
| AWS | [sns](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#sns) | This command enumerates all of the sns topics and gives you the commands to subscribe to a topic or send messages to a topic (if you have the permissions needed). This command only deals with topics, and not the SMS functionality. This command also attempts to summarize topic resource policies if they exist.|
| AWS | [sqs](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#sqs) | This command enumerates all of the sqs queues and gives you the commands to receive messages from a queue and send messages to a queue (if you have the permissions needed). This command also attempts to summarize queue resource policies if they exist.|
| AWS | [tags](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#tags) | List all resources with tags, and all of the tags. This can be used similar to inventory as another method to identify what types of resources exist in an account. |
| AWS | [workloads](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#workloads) | List all of the compute workloads and what role they have.  Tells you if any of the roles are admin (bad) and if you have pmapper data locally, it will tell you if any of the roles can privesc to admin (also bad) |
| AWS | [ds](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#workloads) | List all of the AWS-managed directories and their attributes. Also summarizes the current trusts with their directions and types. |


# Azure Commands
| Provider | Command Name | Description 
| - | - | - | 
| Azure | [whoami](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#whoami) | Displays information on the tenant, subscriptions and resource groups available to your current Azure CLI session. This is useful to provide situation awareness on what tenant and subscription IDs to use with the other sub commands. | 
| Azure | [inventory](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#inventory) | Display an inventory table of all resources per location. | 
| Azure | [rbac](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#rbac) | Lists Azure RBAC role assignments at subscription or tenant level |
| Azure | [storage](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#storage) | The storage command is still under development. Currently it only displays limited data about the storage accounts | 
| Azure | [vms](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#vms) | Enumerates useful information for Compute instances in all available resource groups and subscriptions | 


# GCP Commands

## Identity & Access Management
| Provider | Command Name | Description |
| - | - | - |
| GCP | whoami | Display identity context for the authenticated GCP user/service account |
| GCP | iam | Enumerate GCP IAM principals across organizations, folders, and projects |
| GCP | permissions | Enumerate ALL permissions for each IAM entity with full inheritance explosion |
| GCP | serviceaccounts | Enumerate GCP service accounts with security analysis |
| GCP | service-agents | Enumerate Google-managed service agents |
| GCP | keys | Enumerate all GCP keys (SA keys, HMAC keys, API keys) |
| GCP | resource-iam | Enumerate IAM policies on GCP resources (buckets, datasets, secrets, etc.) |
| GCP | domain-wide-delegation | Find service accounts with Domain-Wide Delegation to Google Workspace |
| GCP | privesc | Identify privilege escalation paths in GCP projects |

## Compute & Containers
| Provider | Command Name | Description |
| - | - | - |
| GCP | instances | Enumerate GCP Compute Engine instances with security configuration |
| GCP | gke | Enumerate GKE clusters with security analysis |
| GCP | cloudrun | Enumerate Cloud Run services and jobs with security analysis |
| GCP | functions | Enumerate GCP Cloud Functions with security analysis |
| GCP | app-engine | Enumerate App Engine applications and security configurations |
| GCP | composer | Enumerate Cloud Composer environments |
| GCP | dataproc | Enumerate Dataproc clusters |
| GCP | dataflow | Enumerate Dataflow jobs and pipelines |
| GCP | notebooks | Enumerate Vertex AI Workbench notebooks |
| GCP | workload-identity | Enumerate GKE Workload Identity and Workload Identity Federation |

## Storage & Databases
| Provider | Command Name | Description |
| - | - | - |
| GCP | buckets | Enumerate GCP Cloud Storage buckets with security configuration |
| GCP | bucket-enum | Enumerate GCS buckets for sensitive files (credentials, secrets, configs) |
| GCP | bigquery | Enumerate GCP BigQuery datasets and tables with security analysis |
| GCP | cloudsql | Enumerate Cloud SQL instances with security analysis |
| GCP | spanner | Enumerate Cloud Spanner instances and databases |
| GCP | bigtable | Enumerate Cloud Bigtable instances and tables |
| GCP | filestore | Enumerate Filestore NFS instances |
| GCP | memorystore | Enumerate Memorystore (Redis) instances |

## Networking
| Provider | Command Name | Description |
| - | - | - |
| GCP | vpc-networks | Enumerate VPC Networks |
| GCP | firewall | Enumerate VPC networks and firewall rules with security analysis |
| GCP | loadbalancers | Enumerate Load Balancers |
| GCP | dns | Enumerate Cloud DNS zones and records with security analysis |
| GCP | endpoints | Enumerate all network endpoints (external and internal) with IPs, ports, and hostnames |
| GCP | private-service-connect | Enumerate Private Service Connect endpoints and service attachments |
| GCP | network-topology | Visualize VPC network topology, peering relationships, and trust boundaries |

## Security & Compliance
| Provider | Command Name | Description |
| - | - | - |
| GCP | vpc-sc | Enumerate VPC Service Controls |
| GCP | access-levels | Enumerate Access Context Manager access levels |
| GCP | cloud-armor | Enumerate Cloud Armor security policies and find weaknesses |
| GCP | iap | Enumerate Identity-Aware Proxy configurations |
| GCP | beyondcorp | Enumerate BeyondCorp Enterprise configurations |
| GCP | kms | Enumerate Cloud KMS key rings and crypto keys with security analysis |
| GCP | secrets | Enumerate GCP Secret Manager secrets with security configuration |
| GCP | cert-manager | Enumerate SSL/TLS certificates and find expiring or misconfigured certs |
| GCP | org-policies | Enumerate organization policies and identify security weaknesses |

## CI/CD & Source Control
| Provider | Command Name | Description |
| - | - | - |
| GCP | artifact-registry | Enumerate GCP Artifact Registry and Container Registry with security configuration |
| GCP | cloudbuild | Enumerate Cloud Build triggers and builds |
| GCP | source-repos | Enumerate Cloud Source Repositories |
| GCP | scheduler | Enumerate Cloud Scheduler jobs with security analysis |

## Messaging & Events
| Provider | Command Name | Description |
| - | - | - |
| GCP | pubsub | Enumerate Pub/Sub topics and subscriptions with security analysis |

## Logging & Monitoring
| Provider | Command Name | Description |
| - | - | - |
| GCP | logging | Enumerate Cloud Logging sinks and metrics with security analysis |
| GCP | logging-gaps | Find resources with missing or incomplete logging |

## Organization & Projects
| Provider | Command Name | Description |
| - | - | - |
| GCP | organizations | Enumerate GCP organization hierarchy |
| GCP | asset-inventory | Enumerate Cloud Asset Inventory with optional dependency analysis |
| GCP | backup-inventory | Enumerate backup policies, protected resources, and identify backup gaps |

## Attack Path Analysis
| Provider | Command Name | Description |
| - | - | - |
| GCP | lateral-movement | Map lateral movement paths, credential theft vectors, and pivot opportunities |
| GCP | data-exfiltration | Identify data exfiltration paths, potential vectors, and missing security hardening |
| GCP | public-access | Find resources with allUsers/allAuthenticatedUsers access across 16 GCP services |
| GCP | cross-project | Analyze cross-project IAM bindings, logging sinks, and Pub/Sub exports for lateral movement |



# Authors
* [Carlos Vendramini](https://github.com/carlosvendramini-bf)
* [Seth Art (@sethsec](https://twitter.com/sethsec))
* Joseph Barcia

# Contributing
[Wiki - How to Contribute](https://github.com/BishopFox/cloudfox/wiki#how-to-contribute)


# FAQ

**How does CloudFox compare with ScoutSuite, Prowler, Steampipe's AWS Compliance Module, AWS Security Hub, etc.**

CloudFox doesn't create any alerts or findings, and doesn't check your environment for compliance to a baseline or benchmark. Instead, it simply enables you to be more efficient during your manual penetration testing activities. If gives you the information you'll likely need to validate whether an attack path is possible or not. 

**Why do I see errors in some CloudFox commands?**

* Services that don't exist in all regions - CloudFox tries a few ways to figure out what services are supported in each region. However some services don't support the methods CloudFox uses, so CloudFox defaults to just asking every region about the service. Regions that don't support the service will return errors. 
* You don't have permission - Another reason you might see errors if you don't have permissions to make calls that CloudFox is making. Either because the policy doesn't allow it (e.g., SecurityAudit doesn't allow all of the permissions CloudFox needs. Or, it might be an SCP that is blocking you.  

You can always look in the ~/.cloudfox/cloudfox-error.log file to get more information on errors. 

# Prior work and other related projects 
* [SmogCloud](https://github.com/BishopFox/smogcloud) - Inspiration for the `endpoints` command
* [SummitRoute's AWS Exposable Resources](https://github.com/SummitRoute/aws_exposable_resources)  - Inspiration for the `endpoints` command
* [Steampipe](https://steampipe.io/) - We used steampipe to prototype many cloudfox commands. While CloudFox is laser focused on helping cloud penetration testers, steampipe is an easy way to query any and all of your cloud resources. 
* [Principal Mapper](https://github.com/nccgroup/PMapper) - Inspiration for, and a strongly recommended partner to the `iam-simulator` command
* [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - Inspiration for the `permissions` command
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Excellent cloud security benchmark tool. Provided inspiration for the `--userdata` functionality in the `instances` command, the `permissions` command, and many others
* [Prowler](https://github.com/prowler-cloud/prowler) - Another excellent cloud security benchmark tool. 
* [Pacu](https://github.com/RhinoSecurityLabs/pacu) - Excellent cloud penetration testing tool. PACU has quite a few enumeration commands similar to CloudFox, and lots of other commands that automate exploitation tasks (something that CloudFox avoids by design) 
 * [CloudMapper](https://github.com/duo-labs/cloudmapper) - Inspiration for the `inventory` command and just generally CloudFox as a whole 
