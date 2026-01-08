#!/bin/bash
#
# FTC Pool Server AWS Deployment Script
# Creates EC2 instance in Seoul + Global Accelerator
#

set -e

# Configuration
REGION="ap-northeast-2"                    # Seoul
INSTANCE_TYPE="t3.medium"                  # 2 vCPU, 4GB RAM
AMI_ID="ami-0c9c942bd7bf113a2"             # Amazon Linux 2023 (Seoul)
KEY_NAME="ftc-pool-key"                    # SSH key name
SECURITY_GROUP_NAME="ftc-pool-sg"
INSTANCE_NAME="ftc-pool-server"

# FTC Node internal IP (replace with your node's private IP)
FTC_NODE_IP="${FTC_NODE_IP:-10.0.0.100}"

echo "=== FTC Pool Server AWS Deployment ==="
echo "Region: $REGION"
echo ""

# Step 1: Create SSH Key Pair (if not exists)
echo "Creating SSH key pair..."
aws ec2 describe-key-pairs --key-names $KEY_NAME --region $REGION 2>/dev/null || \
aws ec2 create-key-pair --key-name $KEY_NAME --region $REGION \
    --query 'KeyMaterial' --output text > ${KEY_NAME}.pem
chmod 400 ${KEY_NAME}.pem 2>/dev/null || true
echo "Key pair ready: ${KEY_NAME}"

# Step 2: Create Security Group
echo ""
echo "Creating security group..."
VPC_ID=$(aws ec2 describe-vpcs --region $REGION --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)

SG_ID=$(aws ec2 describe-security-groups --region $REGION \
    --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")

if [ "$SG_ID" == "None" ] || [ -z "$SG_ID" ]; then
    SG_ID=$(aws ec2 create-security-group \
        --group-name $SECURITY_GROUP_NAME \
        --description "FTC Pool Server Security Group" \
        --vpc-id $VPC_ID \
        --region $REGION \
        --query 'GroupId' --output text)

    # Allow SSH (22), Stratum (3333)
    aws ec2 authorize-security-group-ingress --group-id $SG_ID --region $REGION \
        --ip-permissions \
        IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0,Description="SSH"}]' \
        IpProtocol=tcp,FromPort=3333,ToPort=3333,IpRanges='[{CidrIp=0.0.0.0/0,Description="Stratum"}]'
fi
echo "Security group: $SG_ID"

# Step 3: User data script for instance setup
USER_DATA=$(cat << 'USERDATA'
#!/bin/bash
yum update -y
yum install -y nodejs npm git

# Create app directory
mkdir -p /opt/ftc-pool
cd /opt/ftc-pool

# Create package.json
cat > package.json << 'EOF'
{
  "name": "ftc-pool-server",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": { "start": "node server.js" }
}
EOF

# Create systemd service
cat > /etc/systemd/system/ftc-pool.service << 'EOF'
[Unit]
Description=FTC Mining Pool Server
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/ftc-pool
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=NODE_HOST=FTC_NODE_PLACEHOLDER
Environment=NODE_RPC_PORT=17318
Environment=NODE_RPC_USER=ftcuser
Environment=NODE_RPC_PASS=ftcpass
Environment=POOL_PORT=3333

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "Setup complete. Upload server.js to /opt/ftc-pool/ and run: systemctl start ftc-pool"
USERDATA
)

# Replace placeholder with actual node IP
USER_DATA=$(echo "$USER_DATA" | sed "s/FTC_NODE_PLACEHOLDER/$FTC_NODE_IP/")

# Step 4: Launch EC2 Instance
echo ""
echo "Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id $AMI_ID \
    --instance-type $INSTANCE_TYPE \
    --key-name $KEY_NAME \
    --security-group-ids $SG_ID \
    --user-data "$USER_DATA" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
    --region $REGION \
    --query 'Instances[0].InstanceId' --output text)

echo "Instance ID: $INSTANCE_ID"
echo "Waiting for instance to be running..."

aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region $REGION

# Get public IP
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --region $REGION \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "Instance Public IP: $PUBLIC_IP"

# Step 5: Create Global Accelerator
echo ""
echo "Creating Global Accelerator..."

GA_ARN=$(aws globalaccelerator create-accelerator \
    --name "ftc-pool-accelerator" \
    --ip-address-type IPV4 \
    --enabled \
    --query 'Accelerator.AcceleratorArn' --output text)

echo "Accelerator ARN: $GA_ARN"

# Wait for accelerator to be deployed
echo "Waiting for accelerator to be deployed..."
sleep 30

# Get accelerator IPs
GA_IPS=$(aws globalaccelerator describe-accelerator \
    --accelerator-arn $GA_ARN \
    --query 'Accelerator.IpSets[0].IpAddresses' --output text)

echo "Global Accelerator IPs: $GA_IPS"

# Create listener
LISTENER_ARN=$(aws globalaccelerator create-listener \
    --accelerator-arn $GA_ARN \
    --port-ranges FromPort=3333,ToPort=3333 \
    --protocol TCP \
    --query 'Listener.ListenerArn' --output text)

echo "Listener ARN: $LISTENER_ARN"

# Create endpoint group
aws globalaccelerator create-endpoint-group \
    --listener-arn $LISTENER_ARN \
    --endpoint-group-region $REGION \
    --endpoint-configurations "EndpointId=$INSTANCE_ID,Weight=100,ClientIPPreservationEnabled=true"

echo ""
echo "=== DEPLOYMENT COMPLETE ==="
echo ""
echo "EC2 Instance:"
echo "  ID: $INSTANCE_ID"
echo "  IP: $PUBLIC_IP"
echo "  SSH: ssh -i ${KEY_NAME}.pem ec2-user@$PUBLIC_IP"
echo ""
echo "Global Accelerator:"
echo "  IPs: $GA_IPS"
echo "  DNS: Configure pool.flowprotocol.net -> $GA_IPS"
echo ""
echo "Next steps:"
echo "1. SCP server.js to instance: scp -i ${KEY_NAME}.pem server.js ec2-user@$PUBLIC_IP:/opt/ftc-pool/"
echo "2. SSH to instance and start service: systemctl start ftc-pool"
echo "3. Configure DNS: pool.flowprotocol.net -> Global Accelerator IP"
