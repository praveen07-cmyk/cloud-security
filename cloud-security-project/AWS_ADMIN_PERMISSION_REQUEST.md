# AWS Admin Permission Request (Updated)

**IAM User ARN**: `arn:aws:iam::774075583705:user/cloud-security-monitor`  
**Current Policy**: `CloudSecurityReadOnly` (arn:aws:iam::774075583705:policy/CloudSecurityReadOnly) - Version `v1`  
**Status**: The policy `cloudsec-runtime-policy` is **NOT ATTACHED** to the user.

**Exact Administrator Action Required**:
Please attach `infra/cloudsec-runtime-policy.json` (or add its statements to `CloudSecurityReadOnly`) for `arn:aws:iam::774075583705:user/cloud-security-monitor`.

**Policy Summary**:
1. **STS Validation**: `sts:GetCallerIdentity` on `Resource: "*"`
2. **Global Discovery/List Actions**: `cloudtrail:DescribeTrails`, `cloudtrail:ListTrails`, `events:ListRules`, `sqs:ListQueues` on `Resource: "*"` (AWS requires wildcard for list operations).
3. **Scoped Resource Read Actions**: `cloudtrail:GetTrailStatus`, `events:DescribeRule`, `events:ListTargetsByRule`, `sqs:GetQueueUrl`, `sqs:GetQueueAttributes` scoped to `arn:aws:*:ap-south-1:774075583705:cloudsec-*`.
4. **Worker Message Operations**: `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility` scoped to `arn:aws:sqs:ap-south-1:774075583705:cloudsec-*`.

**Policy Files**:
- [cloudsec-runtime-policy.json](infra/cloudsec-runtime-policy.json)
- [cloudsec-deployment-policy.json](infra/cloudsec-deployment-policy.json)
