#!/bin/bash 

# Set the AWS region
aws_region="us-east-1"

# Check if user wants to retrieve information for all profiles or just one
read -p "Enter the AWS profile name to retrieve instance information from, or type 'all' to retrieve information for all profiles: " aws_profile_input

# Prompt user for output format
while true; do
    read -p "Choose the output format (csv or md): " output_format
    case $output_format in
        [Cc][Ss][Vv]|[Mm][Dd]) break;;
        *) echo "Invalid format. Please choose either 'csv' or 'md'.";;
    esac
done

# Retrieve list of profile names
if [[ "$aws_profile_input" = "all" ]]; then
    aws_profile_list=($(cat $HOME/awsjson/aws-account-name.lst))
else
    aws_profile_list=("$aws_profile_input")
fi

# Set output file name
if [[ "$aws_profile_input" = "all" ]]; then
    output_file="AllCommons-Inventory.${output_format}"
else
    output_file="${aws_profile_input}-Inventory.${output_format}"
fi

# Add date to output file name if it exists
if [ -e "$output_file" ]; then
    today=$(date +"%m%d%Y")
    output_file="${output_file%.${output_format}}-${today}.${output_format}"
fi

# Set output directory and create it if it doesn't exist
output_directory="$HOME/awsjson/log/"
mkdir -p "$output_directory"

# Set full output file path
output_file_path="${output_directory}${output_file}"

# Print the header
if [ "$output_format" = "csv" ]; then
    header="AWS Profile,Instance ID,Instance Name,Platform Type,Platform Name,Key Name,Platform Version\n"
else
    header="| AWS Profile | Instance ID | Instance Name | Platform Type | Platform Name | Key Name | Platform Version |\n| ----------- | ----------- | ------------- | ------------- | -------------- | -------- | ---------------- |\n"
fi
printf '%s' "$header" > "$output_file_path"

# Loop through AWS profile names and retrieve instance information for each profile
for aws_profile in "${aws_profile_list[@]}"; do
    aws --profile "$aws_profile" ssm describe-instance-information --region "$aws_region" --query "InstanceInformationList[*].{InstanceId: InstanceId, PlatformName: PlatformName, PlatformType: PlatformType, PlatformVersion: PlatformVersion}" | jq -r '.[] | [.InstanceId, .PlatformType, .PlatformName, (.PlatformVersion // "N/A")] | @csv' | while read -r line; do
        # Extract the instance ID and platform type from the output
        instance_id=$(echo "$line" | cut -d',' -f1 | tr -d '"')

        platform_type=$(echo "$line" | cut -d',' -f2 | tr -d '"')
        platform_name=$(echo "$line" | cut -d',' -f3 | tr -d '"')
        platform_version=$(echo "$line" | cut -d',' -f4 | tr -d '"')

        # Retrieve the key name using the EC2 command
        key_name=$(aws --profile "$aws_profile" ec2 describe-instances --region "$aws_region" --instance-ids "$instance_id" --query "Reservations[].Instances[].KeyName" --output text)

        # Retrieve the tag value for the "Name" tag using the EC2 command
        instance_tag_value=$(aws --profile "$aws_profile" ec2 describe-tags --region "$aws_region" --filters "Name=resource-id,Values=$instance_id" "Name=key,Values=Name" --query "Tags[].Value" --output text)

        # Print the output, including the key name and tag value
        if [ "$output_format" = "csv" ]; then
            printf '%s,%s,%s,%s,%s,%s,%s\n' "$aws_profile" "$instance_id" "${instance_tag_value:-N/A}" "$platform_type" "$platform_name" "$key_name" "$platform_version" >> "$output_file_path"
        else
            printf '| %-11s | %-10s | %-12s | %-11s | %-12s | %-6s | %-14s |\n' "$aws_profile" "$instance_id" "${instance_tag_value:-N/A}" "$platform_type" "$platform_name" "$key_name" "$platform_version" >> "$output_file_path"
        fi
    done
done

