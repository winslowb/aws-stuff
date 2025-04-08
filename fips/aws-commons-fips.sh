#!/bin/bash

# Function to list AWS profiles
list_profiles() {
  grep -oE '^\[\w+\]' $HOME/.aws/credentials | tr -d '[]'
}

# Function to check FIPS status for a given instance
check_fips_status() {
  local instance_id=$1
  local profile=$2
  local region=$3

  # Send command to check FIPS status
  command_id=$(aws ssm send-command --document-name "AWS-RunShellScript" \
                                    --targets "Key=instanceids,Values=${instance_id}" \
                                    --parameters "commands=cat /proc/sys/crypto/fips_enabled" \
                                    --profile $profile --region $region \
                                    --output text --query "Command.CommandId" 2>/dev/null)
  
  # If the command was not sent successfully, mark as "Check Manually"
  if [ -z "$command_id" ]; then
    echo "Check Manually"
    return
  fi
  
  # Wait briefly to allow command execution to start
  sleep 5

  # Retrieve command output
  output=$(aws ssm get-command-invocation --command-id "$command_id" \
                                          --instance-id "$instance_id" \
                                          --profile $profile --region $region \
                                          --output text --query "StandardOutputContent" 2>/dev/null)

  if [ "$output" == "1" ]; then
    echo "Enabled"
  elif [ "$output" == "0" ]; then
    echo "Disabled"
  else
    echo "Check Manually"
  fi
}

# Function to generate report
generate_report() {
  local profile_name=$1
  local region=$2
  mkdir -p $HOME/aws-reports
  local report_path="$HOME/aws-reports/${profile_name}_${region}.md"

  # Header for the markdown report
  echo "| Profile Name | Region | InstanceId | Key:Name Tag:Name | EKS Node | Cluster Name | FIPS |" > $report_path
  echo "|--------------|--------|------------|-------------------|----------|--------------|------|" >> $report_path

  # Fetching all instance details
  aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{InstanceId:InstanceId, Tags:Tags}' \
    --output json --profile $profile_name --region $region | \
    jq -r '.[][] | select(.Tags[]?.Key | contains("kubernetes.io/cluster/")) | 
            {InstanceId: .InstanceId, 
             NameTag: (.Tags[]? | select(.Key=="Name") | .Value), 
             ClusterTag: (.Tags[]? | select(.Key | startswith("kubernetes.io/cluster/")) | .Key)} | 
            [.InstanceId, .NameTag, .ClusterTag] | @tsv' | \
    while IFS=$'\t' read -r instance_id name_tag cluster_tag_key
  do
    local eks_status="Yes"
    local cluster_name="${cluster_tag_key#kubernetes.io/cluster/}"
    local fips_status=$(check_fips_status "$instance_id" "$profile_name" "$region")
    echo "| $profile_name | $region | $instance_id | $name_tag | $eks_status | $cluster_name | $fips_status |" >> $report_path
  done

  echo "Report generated at $report_path"
}

# Main script starts here
echo "Available AWS Profiles:"
options=($(list_profiles) "Quit")  # Create an array of options
PS3='Please select a profile: '
select opt in "${options[@]}"; do  # Use the array in select
    case $opt in
        "Quit") 
            echo "Exiting script."
            break ;;
        *) 
            if [[ " ${options[@]} " =~ " ${opt} " ]]; then
                echo "Selected profile: $opt"
                read -p "Enter region (default us-east-1): " region
                region=${region:-us-east-1}
                generate_report "$opt" "$region"
                break
            else
                echo "Invalid option. Please try again."
            fi ;;
    esac
done
