# AWS IAM PERMISSION GAP REPORT

## 1. Identity Evaluated
- **User**: `arn:aws:iam::774075583705:user/cloud-security-monitor`
- **Attached Policies**: `CloudSecurityReadOnly` (arn:aws:iam::774075583705:policy/CloudSecurityReadOnly)
- **Inline Policies**: None

## 2. Exact Missing Actions
- **EventBridge**: `events:ListRules`, `events:DescribeRule`, `events:ListTargetsByRule`, `events:PutRule`, `events:PutTargets`, `events:RemoveTargets`, `events:DeleteRule`
- **SQS**: `sqs:ListQueues`, `sqs:CreateQueue`, `sqs:SetQueueAttributes`, `sqs:GetQueueAttributes`, `sqs:GetQueueUrl`, `sqs:DeleteQueue`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`
- **CloudTrail**: `cloudtrail:CreateTrail`, `cloudtrail:StartLogging`, `cloudtrail:UpdateTrail`, `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`
- **S3 (for CloudTrail)**: `s3:CreateBucket`, `s3:PutBucketPolicy`, `s3:PutObject` (for trail delivery)

## 3. Proposed Policy
The proposed least-privilege policy has been generated and saved to:
`infra/cloudsec-live-aws-least-privilege-policy.json`

## 4. Intended Resources
- **EventBridge**: `arn:aws:events:ap-south-1:*:rule/cloudsec-*`
- **SQS**: `arn:aws:sqs:ap-south-1:*:cloudsec-*`
- **CloudTrail**: `arn:aws:cloudtrail:ap-south-1:*:trail/cloudsec-*`
- **S3**: `arn:aws:s3:::cloudsec-*`

## 5. Justification
- **Validation Actions** (`ListRules`, `ListQueues`, `DescribeRule`, etc.): Necessary for the Laptop 1 startup checks and runtime verifier to confirm Live AWS Mode is operational.
- **Deployment Actions** (`CreateQueue`, `PutRule`, `CreateTrail`, etc.): Necessary to stand up the CloudTrail -> EventBridge -> SQS infrastructure in the student account.
- **Worker Actions** (`ReceiveMessage`, `DeleteMessage`): Necessary for the background worker to consume events from the SQS queue.
- **S3 Actions**: Required by CloudTrail to deposit the event logs, which then triggers EventBridge.

## 6. IAM Policy Change Capability
The student account appears to grant only `iam:Get*` and `iam:List*` permissions. It is extremely likely that `iam:CreatePolicy` and `iam:AttachUserPolicy` are RESTRICTED. Therefore, an administrator of the student account will likely need to grant these permissions or attach the proposed policy manually.
