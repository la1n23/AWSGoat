#!/bin/bash

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "=== Cleaning up AWS resources ==="

echo "Deleting DynamoDB tables..."
for table in $(aws dynamodb list-tables --query 'TableNames[?contains(@, `blog`) || contains(@, `users`) || contains(@, `posts`)]' --output text); do
    echo "Deleting table: $table"
    aws dynamodb delete-table --table-name "$table" || true
done

echo "Deleting Lambda functions..."
for func in $(aws lambda list-functions --query 'Functions[?contains(FunctionName, `blog`) || contains(FunctionName, `goat`)].FunctionName' --output text); do
    echo "Deleting function: $func"
    aws lambda delete-function --function-name "$func" || true
done

echo "Deleting S3 buckets..."
for bucket in $(aws s3 ls | grep -E "(blog|goat|ec2-temp)" | awk '{print $3}'); do
    if [[ "$bucket" != *"state-files"* ]]; then
        echo "Emptying and deleting bucket: $bucket"
        aws s3 rm s3://"$bucket" --recursive || true
        aws s3 rb s3://"$bucket" || true
    fi
done

echo "Deleting IAM policies..."
for policy in $(aws iam list-policies --scope Local --query 'Policies[?contains(PolicyName, `lambda`) || contains(PolicyName, `blog`) || contains(PolicyName, `goat`) || contains(PolicyName, `ec2`)].PolicyName' --output text); do
    policy_arn="arn:aws:iam::$ACCOUNT_ID:policy/$policy"
    echo "Detaching and deleting policy: $policy"
    
    for role in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" --query 'PolicyRoles[].RoleName' --output text 2>/dev/null); do
        aws iam detach-role-policy --role-name "$role" --policy-arn "$policy_arn" || true
    done
    
    aws iam delete-policy --policy-arn "$policy_arn" || true
done

echo "Deleting IAM roles..."
for role in $(aws iam list-roles --query 'Roles[?contains(RoleName, `blog_app`) || contains(RoleName, `GOAT`) || contains(RoleName, `lambda`)].RoleName' --output text); do
    echo "Cleaning up role: $role"
    
    for profile in $(aws iam list-instance-profiles-for-role --role-name "$role" --query 'InstanceProfiles[].InstanceProfileName' --output text 2>/dev/null); do
        aws iam remove-role-from-instance-profile --instance-profile-name "$profile" --role-name "$role" || true
    done
    
    for policy_arn in $(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n'); do
        aws iam detach-role-policy --role-name "$role" --policy-arn "$policy_arn" || true
    done
    
    for policy_name in $(aws iam list-role-policies --role-name "$role" --query 'PolicyNames[]' --output text 2>/dev/null); do
        aws iam delete-role-policy --role-name "$role" --policy-name "$policy_name" || true
    done
    
    aws iam delete-role --role-name "$role" || true
done

echo "Deleting IAM instance profiles..."
for profile in $(aws iam list-instance-profiles --query 'InstanceProfiles[?contains(InstanceProfileName, `GOAT`) || contains(InstanceProfileName, `blog`)].InstanceProfileName' --output text); do
    echo "Deleting instance profile: $profile"
    
    for role in $(aws iam list-instance-profiles --query "InstanceProfiles[?InstanceProfileName=='$profile'].Roles[].RoleName" --output text 2>/dev/null); do
        aws iam remove-role-from-instance-profile --instance-profile-name "$profile" --role-name "$role" || true
    done
    
    aws iam delete-instance-profile --instance-profile-name "$profile" || true
done

echo "=== Cleanup complete ==="
