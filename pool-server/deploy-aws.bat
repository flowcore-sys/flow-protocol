@echo off
REM FTC Pool Server AWS Deployment (Windows)
REM Run these commands step by step

setlocal

set REGION=ap-northeast-2
set KEY_NAME=ftc-pool-key
set SG_NAME=ftc-pool-sg
set INSTANCE_NAME=ftc-pool-server

echo === FTC Pool Server AWS Deployment ===
echo Region: %REGION% (Seoul)
echo.

REM Step 1: Create Key Pair
echo [Step 1] Creating SSH key pair...
aws ec2 create-key-pair --key-name %KEY_NAME% --region %REGION% --query "KeyMaterial" --output text > %KEY_NAME%.pem 2>nul
if %errorlevel%==0 (
    echo Key saved to %KEY_NAME%.pem
) else (
    echo Key pair already exists or error occurred
)

REM Step 2: Get VPC ID
echo.
echo [Step 2] Getting default VPC...
for /f %%i in ('aws ec2 describe-vpcs --region %REGION% --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text') do set VPC_ID=%%i
echo VPC ID: %VPC_ID%

REM Step 3: Create Security Group
echo.
echo [Step 3] Creating security group...
for /f %%i in ('aws ec2 create-security-group --group-name %SG_NAME% --description "FTC Pool Server" --vpc-id %VPC_ID% --region %REGION% --query "GroupId" --output text 2^>nul') do set SG_ID=%%i
if "%SG_ID%"=="" (
    for /f %%i in ('aws ec2 describe-security-groups --region %REGION% --filters "Name=group-name,Values=%SG_NAME%" --query "SecurityGroups[0].GroupId" --output text') do set SG_ID=%%i
)
echo Security Group: %SG_ID%

REM Add rules
echo Adding firewall rules...
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --region %REGION% --protocol tcp --port 22 --cidr 0.0.0.0/0 2>nul
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --region %REGION% --protocol tcp --port 3333 --cidr 0.0.0.0/0 2>nul

REM Step 4: Launch Instance
echo.
echo [Step 4] Launching EC2 instance...
REM Amazon Linux 2023 AMI for Seoul
set AMI_ID=ami-0c9c942bd7bf113a2

for /f %%i in ('aws ec2 run-instances --image-id %AMI_ID% --instance-type t3.medium --key-name %KEY_NAME% --security-group-ids %SG_ID% --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=%INSTANCE_NAME%}]" --region %REGION% --query "Instances[0].InstanceId" --output text') do set INSTANCE_ID=%%i
echo Instance ID: %INSTANCE_ID%

echo Waiting for instance to start...
aws ec2 wait instance-running --instance-ids %INSTANCE_ID% --region %REGION%

for /f %%i in ('aws ec2 describe-instances --instance-ids %INSTANCE_ID% --region %REGION% --query "Reservations[0].Instances[0].PublicIpAddress" --output text') do set PUBLIC_IP=%%i
echo Public IP: %PUBLIC_IP%

REM Step 5: Create Global Accelerator
echo.
echo [Step 5] Creating Global Accelerator...
for /f %%i in ('aws globalaccelerator create-accelerator --name "ftc-pool-accelerator" --ip-address-type IPV4 --enabled --query "Accelerator.AcceleratorArn" --output text') do set GA_ARN=%%i
echo Accelerator ARN: %GA_ARN%

echo Waiting 30 seconds for accelerator...
timeout /t 30 /nobreak

for /f "tokens=*" %%i in ('aws globalaccelerator describe-accelerator --accelerator-arn %GA_ARN% --query "Accelerator.IpSets[0].IpAddresses[0]" --output text') do set GA_IP=%%i
echo Global Accelerator IP: %GA_IP%

REM Create listener
echo Creating listener...
for /f %%i in ('aws globalaccelerator create-listener --accelerator-arn %GA_ARN% --port-ranges FromPort=3333,ToPort=3333 --protocol TCP --query "Listener.ListenerArn" --output text') do set LISTENER_ARN=%%i
echo Listener ARN: %LISTENER_ARN%

REM Create endpoint group
echo Creating endpoint group...
aws globalaccelerator create-endpoint-group --listener-arn %LISTENER_ARN% --endpoint-group-region %REGION% --endpoint-configurations "EndpointId=%INSTANCE_ID%,Weight=100"

echo.
echo === DEPLOYMENT COMPLETE ===
echo.
echo EC2 Instance: %INSTANCE_ID%
echo Public IP: %PUBLIC_IP%
echo Global Accelerator IP: %GA_IP%
echo.
echo Next steps:
echo 1. SSH: ssh -i %KEY_NAME%.pem ec2-user@%PUBLIC_IP%
echo 2. Upload server.js to /opt/ftc-pool/
echo 3. Configure DNS: pool.flowprotocol.net -^> %GA_IP%
echo.

endlocal
