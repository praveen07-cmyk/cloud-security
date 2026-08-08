# AWS IAM DENIAL DIAGNOSTIC REPORT

## 1. Identity & Environment Summary
- **Caller ARN**: `arn:aws:iam::774075583705:user/cloud-security-monitor`
- **Account ID**: `774075583705`
- **Region**: `ap-south-1`

## 2. Policy Inspection Findings
- **Attached Policies**: `CloudSecurityReadOnly` (`arn:aws:iam::774075583705:policy/CloudSecurityReadOnly`)
- **Inline Policies**: None (`[]`)
- **Policy Versions**: Version `v1` (Default), created 2026-07-11.
- **Permissions Boundary**: None (`PermissionsBoundary` key is absent in `get-user` response).
- **Group Membership**: None.

## 3. Root Cause Analysis
- **Root Cause**: `RUNTIME_POLICY_NOT_ATTACHED`
- **Explanation**: The user `cloud-security-monitor` only has the baseline `CloudSecurityReadOnly` policy attached. The required runtime permissions (`events:ListRules`, `events:DescribeRule`, `events:ListTargetsByRule`, `sqs:ListQueues`, `sqs:GetQueueUrl`, `sqs:GetQueueAttributes`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`) are absent from `CloudSecurityReadOnly` v1 and no secondary runtime policy is attached.

## 4. Denied Operations Log Evidence
- `aws events list-rules`: `AccessDeniedException: User arn:aws:iam::774075583705:user/cloud-security-monitor is not authorized to perform: events:ListRules on resource: arn:aws:events:ap-south-1:774075583705:rule/*`
- `aws events describe-rule --name cloudsec-ai-security-events`: `AccessDeniedException: User arn:aws:iam::774075583705:user/cloud-security-monitor is not authorized to perform: events:DescribeRule on resource: arn:aws:events:ap-south-1:774075583705:rule/cloudsec-ai-security-events`
- `aws sqs list-queues`: `AccessDenied: User arn:aws:iam::774075583705:user/cloud-security-monitor is not authorized to perform: sqs:listqueues on resource: arn:aws:sqs:ap-south-1:774075583705:`

## 5. Corrective Action Required
The administrator must attach `infra/cloudsec-runtime-policy.json` (or update `CloudSecurityReadOnly` with its statements) to `arn:aws:iam::774075583705:user/cloud-security-monitor`. Note that `events:ListRules` and `sqs:ListQueues` MUST use `Resource: "*"` as required by AWS IAM for list operations.
