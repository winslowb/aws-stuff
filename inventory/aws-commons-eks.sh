#!/bin/bash 
#
# Description: 
# Tags: Bill
# Date: 2024-04-10
#

# Ensure the aws-reports directory exists
mkdir -p $HOME/aws-reports

# File and path setup
current_date=$(date '+%Y-%m-%d')
filename="aws-commons-eks-$current_date.md"
report_path="$HOME/aws-reports/$filename"

# Start the report with a title, current date, and table headers
{
  echo "# AWS EKS Clusters Report"
  echo "Report generated on: $(date)"
  echo ""
  echo "| Profile | Cluster Name | Version |"
  echo "|---------|--------------|---------|"
} > $report_path

# Function to append EKS cluster information to the report
append_cluster_info() {
  local profile=$1
  local region=$2
  local report_file=$3

  # Get a list of all EKS clusters for the specified profile and region
  clusters=$(AWS_PROFILE=$profile aws eks list-clusters --region "$region" --query 'clusters[*]' --output text)

  # Iterate over each cluster to get its version
  for cluster in $clusters; do
    version=$(AWS_PROFILE=$profile aws eks describe-cluster --name "$cluster" --region "$region" --query 'cluster.version' --output text)
    echo "| $profile | $cluster | $version |" >> $report_file
  done
}

# Default region
default_region="us-east-1"

# Read profiles from $HOME/.aws/credentials
profiles=$(grep '\[' $HOME/.aws/credentials | sed 's/\[\|\]//g')

# Iterate over each profile
for profile in $profiles; do
  # Append EKS versions in the default region (us-east-1) to the report for each profile
  append_cluster_info "$profile" "$default_region" "$report_path"
done

echo "Report generated at $report_path"
