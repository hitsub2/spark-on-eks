# Spark on EKS Workshop from cluster to Spark

## Architecture

[Image: Image.jpg]
## Environment

### Infrastructure

* EKS Version: 1.32
* Region: us-east-1
* Karpenter: 1.4
* Spark: 3.5
* EC2: graviton

### Operation

Where the following command will be executed

* Amazon Linux 2023
    * tested
* Mac
    * not tested

## Create Minimum IAM Role

**The following steps require an IAM role that can create IAM role. It will create:**

* IAM role for eksctl
* Karpenter SQS
* Karpenter Node Role
* Karpenter Controller Policy

### Setting environment

Please change ACCOUNT_ID, CLUSTER_NAME, AWS_REGION accordingly.

```
export ACCOUNT_ID=724853865853
export AWS_REGION=us-east-1
export CLUSTER_NAME="spark-on-eks-demo"
```

### Create a new policy called eksALLAccess

#### Create New policy file

```
cat > eksallaccess.policy <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "eks:*",
            "Resource": "*"
        },
        {
            "Action": [
                "ssm:GetParameter",
                "ssm:GetParameters"
            ],
            "Resource": [
                "arn:aws:ssm:*:${ACCOUNT_ID}:parameter/aws/*",
                "arn:aws:ssm:*::parameter/aws/*"
            ],
            "Effect": "Allow"
        },
        {
             "Action": [
               "kms:CreateGrant",
               "kms:DescribeKey"
             ],
             "Resource": "*",
             "Effect": "Allow"
        },
        {
             "Action": [
               "logs:PutRetentionPolicy"
             ],
             "Resource": "*",
             "Effect": "Allow"
        }        
    ]
}

EOF
```

#### Create the policy

```
aws iam create-policy \
    --policy-name EKSALLACCESSIAMPolicy \
    --policy-document file://eksallaccess.policy
```


The above command successful response


```
{
    "Policy": {
        "PolicyName": "EKSALLACCESSIAMPolicy",
        "PolicyId": "ANPA2RRFIHV6X6QSQISDK",
        "Arn": "arn:aws:iam::724853865853:policy/EKSALLACCESSIAMPolicy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2025-04-22T13:11:26+00:00",
        "UpdateDate": "2025-04-22T13:11:26+00:00"
    }
}
```

### Create a new policy limitedIAMACCESS

We will use this role with eksctl tool to create eks cluster.

#### Create New policy file

```
cat > iamlimitedaccess.policy <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateInstanceProfile",
                "iam:DeleteInstanceProfile",
                "iam:GetInstanceProfile",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:GetRole",
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:AttachRolePolicy",
                "iam:PutRolePolicy",
                "iam:UpdateAssumeRolePolicy",
                "iam:AddRoleToInstanceProfile",
                "iam:ListInstanceProfilesForRole",
                "iam:PassRole",
                "iam:DetachRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:GetRolePolicy",
                "iam:GetOpenIDConnectProvider",
                "iam:CreateOpenIDConnectProvider",
                "iam:DeleteOpenIDConnectProvider",
                "iam:TagOpenIDConnectProvider",
                "iam:ListAttachedRolePolicies",
                "iam:TagRole",
                "iam:UntagRole",
                "iam:GetPolicy",
                "iam:CreatePolicy",
                "iam:DeletePolicy",
                "iam:ListPolicyVersions"
            ],
            "Resource": [
                "arn:aws:iam::${ACCOUNT_ID}:instance-profile/eksctl-*",
                "arn:aws:iam::${ACCOUNT_ID}:role/eksctl-*",
                "arn:aws:iam::${ACCOUNT_ID}:policy/eksctl-*",
                "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/*",
                "arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup",
                "arn:aws:iam::${ACCOUNT_ID}:role/eksctl-managed-*",
                "arn:aws:iam::${ACCOUNT_ID}:role/${CLUSTER_NAME}-*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:GetUser"
            ],
            "Resource": [
                "arn:aws:iam::${ACCOUNT_ID}:role/*",
                "arn:aws:iam::${ACCOUNT_ID}:user/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": [
                        "eks.amazonaws.com",
                        "eks-nodegroup.amazonaws.com",
                        "eks-fargate.amazonaws.com"
                    ]
                }
            }
        }
    ]
}

EOF
```

#### Create the policy

```
aws iam create-policy \
    --policy-name IAMLIMITEDACCESSIAMPolicy \
    --policy-document file://iamlimitedaccess.policy
```

The above command successful response

```
{
    "Policy": {
        "PolicyName": "IAMLIMITEDACCESSIAMPolicy",
        "PolicyId": "ANPA2RRFIHV6WI3KAG3AR",
        "Arn": "arn:aws:iam::724853865853:policy/IAMLIMITEDACCESSIAMPolicy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2025-04-22T13:14:58+00:00",
        "UpdateDate": "2025-04-22T13:14:58+00:00"
    }
}
```



### Create the iam role for eksctl tools

#### Configure trust relationships

```
cat > eksctltrustrelationships.policy <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Principal": {
                "Service": [
                    "ec2.amazonaws.com"
                ]
            }
        }
    ]
}

EOF
```

### Create  IAM  role

```
aws iam create-role \
  --role-name EKSCTLRole \
  --assume-role-policy-document file://"eksctltrustrelationships.policy"
```

#### Attach role policy AmazonEC2FullAccess

```
aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess \
  --role-name EKSCTLRole
```

#### Attach role policy AWSCloudFormationFullAccess

```
aws iam attach-role-policy \
  --policy-arn arn:aws:iam::aws:policy/AWSCloudFormationFullAccess \
  --role-name EKSCTLRole
```

#### Attach role policy IAMLIMITEDACCESSIAMPolicy

```
aws iam attach-role-policy \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/IAMLIMITEDACCESSIAMPolicy \
  --role-name EKSCTLRole
```

#### Attach role policy EKSALLACCESSIAMPolicy

```
aws iam attach-role-policy \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/EKSALLACCESSIAMPolicy \
  --role-name EKSCTLRole
```

#### Check if all the policy has been added

```
aws iam list-attached-role-policies --role-name EKSCTLRole
```

response:

```
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonEC2FullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
        },
        {
            "PolicyName": "AWSCloudFormationFullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess"
        },
        {
            "PolicyName": "IAMLIMITEDACCESSIAMPolicy",
            "PolicyArn": "arn:aws:iam::724853865853:policy/IAMLIMITEDACCESSIAMPolicy"
        },
        {
            "PolicyName": "EKSALLACCESSIAMPolicy",
            "PolicyArn": "arn:aws:iam::724853865853:policy/EKSALLACCESSIAMPolicy"
        }
    ]
}
```

### Create instance profile

We will attach this instance profile to the operation of EC2.

```
aws iam create-instance-profile --instance-profile-name eksctlinstanceprofile 

aws iam add-role-to-instance-profile --instance-profile-name eksctlinstanceprofile \
--role-name EKSCTLRole
```


#### Create IAM role, SQS, event bridge rules for karpenter

```
export TEMPOUT="$(mktemp)"
export K8S_VERSION="1.32"
export CLUSTER_NAME="spark-on-eks-demo"

curl -fsSL https://raw.githubusercontent.com/aws/karpenter-provider-aws/v"${KARPENTER_VERSION}"/website/content/en/preview/getting-started/getting-started-with-karpenter/cloudformation.yaml  > "${TEMPOUT}" \
&& aws cloudformation deploy \
  --stack-name "Karpenter-${CLUSTER_NAME}" \
  --template-file "${TEMPOUT}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "ClusterName=${CLUSTER_NAME}"
```



#### Attach EKSCTLRole to the ec2 instance(where eksctl is executed)

### Create Karpenter required role, sqs, and eventbridge

#### Set environment

```
export KARPENTER_NAMESPACE="kube-system"
export KARPENTER_VERSION="1.4.0"
export K8S_VERSION="1.32"
export AWS_PARTITION="aws"
export CLUSTER_NAME="spark-on-eks-demo"
export AWS_DEFAULT_REGION="us-east-1"
export TEMPOUT="$(mktemp)"
export ALIAS_VERSION="$(aws ssm get-parameter --name "/aws/service/eks/optimized-ami/${K8S_VERSION}/amazon-linux-2023/x86_64/standard/recommended/image_id" --query Parameter.Value | xargs aws ec2 describe-images --query 'Images[0].Name' --image-ids | sed -r 's/^.*(v[[:digit:]]+).*$/\1/')"
```

#### Install eksctl

```
# for ARM systems, set ARCH to: `arm64`, `armv6` or `armv7`
ARCH=amd64
PLATFORM=$(uname -s)_$ARCH

curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_$PLATFORM.tar.gz"

# (Optional) Verify checksum
curl -sL "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_checksums.txt" | grep $PLATFORM | sha256sum --check

tar -xzf eksctl_$PLATFORM.tar.gz -C /tmp && rm eksctl_$PLATFORM.tar.gz

sudo mv /tmp/eksctl /usr/local/bin
```

#### Check eksctl version

```
eksctl version
```

response

```
0.207.0
```

#### Install or update aws cli version to 2.x

```
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

#### Check aws cli version

```
aws version
```


response

```
aws-cli/2.16.4 Python/3.11.8 Linux/6.1.90-99.173.amzn2023.x86_64 exe/x86_64.amzn.2023
```




## Create EKS cluster with eksctl

### Install kubectl

```
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

### Prepare eksctl yaml files

eksctl leverage yaml files to create eks cluster which is more production-ready than aws console.

The yaml need to be changed accordingly:

* VPC info
* Managed node groups

```
cat > eksctl_cluster.yaml <<EOF

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_DEFAULT_REGION}
  version: "${K8S_VERSION}"
  tags:
    karpenter.sh/discovery: ${CLUSTER_NAME}

vpc:
  id: "vpc-0f8998f3eccfef6d8"  # (optional, must match VPC ID used for each subnet below)
  subnets:
    # must provide 'private' and/or 'public' subnets by availability zone as shown
    private:
      us-east-1d:
        id: "subnet-0966df9f9e5d84906"
      us-east-1c:
        id: "subnet-0984484352e026b97"
    public:
      us-east-1d:
        id: "subnet-030f0ffbf29c7100f"

      us-east-1c:
        id: "subnet-0039662077df524f0"
iam:
  withOIDC: true
  serviceAccounts:
  - metadata:
      name: karpenter
      namespace: "${KARPENTER_NAMESPACE}"
    roleName: ${CLUSTER_NAME}-karpenter
    attachPolicyARNs:
    - arn:${AWS_PARTITION}:iam::${ACCOUNT_ID}:policy/KarpenterControllerPolicy-${CLUSTER_NAME}
    roleOnly: true
    
iamIdentityMappings:
- arn: "arn:${AWS_PARTITION}:iam::${ACCOUNT_ID}:role/KarpenterNodeRole-${CLUSTER_NAME}"
  username: system:node:{{EC2PrivateDNSName}}
  groups:
  - system:bootstrappers
  - system:nodes
  ## If you intend to run Windows workloads, the kube-proxy group should be specified.
  # For more information, see https://github.com/aws/karpenter/issues/5099.
  # - eks:kube-proxy-windows

managedNodeGroups:
- instanceType: m5.large
  amiFamily: AmazonLinux2023
  name: ${CLUSTER_NAME}-ng
  desiredCapacity: 2
  minSize: 1
  maxSize: 10

EOF
```

#### Creat the cluster

It will take about 20 minutes to create the cluster.

```
eksctl create cluster -f eksctl_cluster.yaml
```



## Install Karpenter

### Prepare subnet and security group

Karpenter using tags to select security group and subnets for new launching EC2 instance.

#### add tags to subnet

```
for NODEGROUP in $(aws eks list-nodegroups --cluster-name "${CLUSTER_NAME}" --query 'nodegroups' --output text); do
    aws ec2 create-tags \
        --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}" \
        --resources $(aws eks describe-nodegroup --cluster-name "${CLUSTER_NAME}" \
        --nodegroup-name "${NODEGROUP}" --query 'nodegroup.subnets' --output text )
done
```

#### add tags to security group

```
NODEGROUP=$(aws eks list-nodegroups --cluster-name "${CLUSTER_NAME}" \
--query 'nodegroups[0]' --output text)
LAUNCH_TEMPLATE=$(aws eks describe-nodegroup --cluster-name "${CLUSTER_NAME}" \
    --nodegroup-name "${NODEGROUP}" --query 'nodegroup.launchTemplate.{id:id,version:version}' \
--output text | tr -s "\t" ",")
SECURITY_GROUPS="$(aws ec2 describe-launch-template-versions \
    --launch-template-id "${LAUNCH_TEMPLATE%,*}" --versions "${LAUNCH_TEMPLATE#*,}" \
--query 'LaunchTemplateVersions[0].LaunchTemplateData.[NetworkInterfaces[0].Groups||SecurityGroupIds]' \
--output text)"

aws ec2 create-tags \
--tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}" \
--resources "${SECURITY_GROUPS}"
```

### Install karpenter

#### Install helm cli

```
wget https://get.helm.sh/helm-v3.17.3-linux-amd64.tar.gz
tar -zxvf helm-v3.17.3-linux-amd64.tar.gz 
sudo mv linux-amd64/helm /usr/local/bin/helm
```

#### Install helm chart

```
export KARPENTER_IAM_ROLE_ARN="arn:${AWS_PARTITION}:iam::${ACCOUNT_ID}:role/${CLUSTER_NAME}-karpenter"
helm registry logout public.ecr.aws

helm upgrade --install karpenter oci://public.ecr.aws/karpenter/karpenter --version "${KARPENTER_VERSION}" --namespace "${KARPENTER_NAMESPACE}" --create-namespace \
--set "serviceAccount.annotations.eks\.amazonaws\.com/role-arn=${KARPENTER_IAM_ROLE_ARN}" \
--set "settings.clusterName=${CLUSTER_NAME}" \
--set "settings.interruptionQueue=${CLUSTER_NAME}" \
--set controller.resources.requests.cpu=1 \
--set controller.resources.requests.memory=1Gi \
--set controller.resources.limits.cpu=1 \
--set controller.resources.limits.memory=1Gi \
--wait
```

#### Check if karpenter is up

```
kubectl logs -f -n "${KARPENTER_NAMESPACE}" -l app.kubernetes.io/name=karpenter -c controller
```

#### Configure nodepool and ec2nodeclass

```
cat <<EOF | envsubst | kubectl apply -f -
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: default
spec:
  template:
    spec:
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["amd64"]
        - key: kubernetes.io/os
          operator: In
          values: ["linux"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand"]
        - key: karpenter.k8s.aws/instance-category
          operator: In
          values: ["c", "m", "r"]
        - key: karpenter.k8s.aws/instance-generation
          operator: Gt
          values: ["2"]
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: default
      expireAfter: 720h # 30 * 24h = 720h
  limits:
    cpu: 1000
  disruption:
    consolidationPolicy: WhenEmptyOrUnderutilized
    consolidateAfter: 1m
---
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata:
  name: default
spec:
  role: "KarpenterNodeRole-${CLUSTER_NAME}" # replace with your cluster name
  amiSelectorTerms:
    - alias: "al2023@${ALIAS_VERSION}"
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: "${CLUSTER_NAME}" # replace with your cluster name
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "${CLUSTER_NAME}" # replace with your cluster name
EOF
```



#### Testing Karpenter if is ok



```
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inflate
spec:
  replicas: 0
  selector:
    matchLabels:
      app: inflate
  template:
    metadata:
      labels:
        app: inflate
    spec:
      terminationGracePeriodSeconds: 0
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
      containers:
      - name: inflate
        image: public.ecr.aws/eks-distro/kubernetes/pause:3.7
        resources:
          requests:
            cpu: 1
        securityContext:
          allowPrivilegeEscalation: false
EOF

kubectl scale deployment inflate --replicas 5
kubectl logs -f -n "${KARPENTER_NAMESPACE}" -l app.kubernetes.io/name=karpenter -c controller
```

#### Get nodeclaim 

nodeclaim is a crd that karpenter use to manage ec2.

```
kubectl get nodeclaim
```


#### scale down the deployment

```
kubectl delete deployment inflate
kubectl logs -f -n "${KARPENTER_NAMESPACE}" -l app.kubernetes.io/name=karpenter -c controller
```



## Submit Spark jobs

### Native

#### Install the spark-submit command

```
wget https://dlcdn.apache.org/spark/spark-3.5.5/spark-3.5.5-bin-hadoop3.tgz
du -sh spark-3.5.5-bin-hadoop3.tgz 
tar zxvf spark-3.5.5-bin-hadoop3.tgz 
```

#### Create a file, and upload to s3

```
cat > input.csv <<EOF 
id,name,amount,date
1,John Doe,500,2025-01-15
2,Jane Smith,1200,2025-01-16
3,Bob Johnson,75,2025-01-17
4,Alice Brown,950,2025-01-18
5,Charlie Davis,1500,2025-01-19
6,Eva Wilson,250,2025-01-20
7,Frank Miller,1800,2025-01-21
8,Grace Lee,90,2025-01-22
9,Henry Garcia,1100,2025-01-23
10,Ivy Robinson,300,2025-01-24

EOF
```



#### Upload file to S3 bucket



#### Update KUBERNETES_MASTER, S3_BUCKET

Please change KUBERNETES_MASTER, S3_BUCKET, SPARK_IMAGE

```
export SPARK_NAMESPACE="spark-jobs"
kubectl create ns $SPARK_NAMESPACE
export KUBERNETES_MASTER="k8s://https://F4EE7FBA0DB4B70203DC4DFA9B39FCB7.gr7.us-east-1.eks.amazonaws.com"
export S3_BUCKET="airbyte-eks-123456"
export SPARK_IMAGE="public.ecr.aws/data-on-eks/spark:3.5.3-scala2.12-java17-python3-ubuntu-s3table0.1.3-iceberg1.6.1"
```


#### Create Python function file

```
# Create a local copy of the script
cat > local_script.py << EOL
#!/usr/bin/env python3
"""
Simple PySpark job to read data from S3 and perform basic processing
"""
from pyspark.sql import SparkSession
from pyspark.sql.functions import col

def main():
    # Initialize Spark Session with S3 configurations
    spark = SparkSession.builder \
        .appName("SimpleS3Reader") \
        .getOrCreate()

    # Set log level
    spark.sparkContext.setLogLevel("INFO")

    try:
        # Read data from S3 bucket
        input_path = "s3a://airbyte-eks-123456/data/input.csv"
        print(f"Reading data from {input_path}")

        # Read CSV data
        df = spark.read.format("csv") \
            .option("header", "true") \
            .option("inferSchema", "true") \
            .load(input_path)

        # Show data summary
        print(f"Loaded {df.count()} records")
        print("Schema:")
        df.printSchema()

        # Simple transformation - select specific columns and filter
        if "amount" in df.columns:
            result_df = df.select("id", "name", "amount") \
                .filter(col("amount") > 100)
            print(f"Records with amount > 100: {result_df.count()}")

            # Show sample results
            print("Sample results:")
            result_df.show(5)

            # Save results back to S3
            output_path = "s3a://airbyte-eks-123456/data/output"
            result_df.write \
                .format("parquet") \
                .mode("overwrite") \
                .save(output_path)

            print(f"Results saved to {output_path}")

    except Exception as e:
        print(f"Error processing data: {str(e)}")
        raise
    finally:
        spark.stop()

if __name__ == "__main__":
    main()
EOL
```

#### Create service account for spark-driver pod

```
cat > spark-sa.yaml << EOL
---
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spark-sa
  namespace: ${SPARK_NAMESPACE}
---
# Role with permissions to create and list pods
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-admin-role
  namespace: ${SPARK_NAMESPACE}
rules:
- apiGroups: [""]
  resources: ["pods", "configmaps"]
  verbs: ["create", "list", "get", "watch"]
---
# RoleBinding to bind the service account to the role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-admin-binding
  namespace: ${SPARK_NAMESPACE}
subjects:
- kind: ServiceAccount
  name: spark-sa
  namespace: ${SPARK_NAMESPACE}
roleRef:
  kind: Role
  name: pod-admin-role
  apiGroup: rbac.authorization.k8s.io

```

```
kubectl apply -f spark-sa.yaml
```

#### Submit spark jobs with spark-submit


We will use secret key and access key for this examples

```
spark-3.5.5-bin-hadoop3/bin/spark-submit \
  --master ${KUBERNETES_MASTER} \
  --deploy-mode cluster \
  --name spark-s3-reader \
  --conf spark.kubernetes.container.image=${SPARK_IMAGE} \
  --conf spark.kubernetes.namespace=${SPARK_NAMESPACE} \
  --conf spark.kubernetes.driver.request.cores=1 \
  --conf spark.kubernetes.driver.limit.cores=1 \
  --conf spark.kubernetes.executor.request.cores=1 \
  --conf spark.kubernetes.executor.limit.cores=1 \
  --conf spark.driver.memory=2g \
  --conf spark.executor.memory=2g \
  --conf spark.executor.instances=2 \
  --conf spark.hadoop.fs.s3a.endpoint=s3.amazonaws.com \
  --conf spark.hadoop.fs.s3a.impl=org.apache.hadoop.fs.s3a.S3AFileSystem \
  --conf spark.hadoop.fs.s3a.aws.credentials.provider=org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider \
  --conf spark.hadoop.fs.s3a.access.key=$(aws configure get aws_access_key_id) \
  --conf spark.hadoop.fs.s3a.secret.key=$(aws configure get aws_secret_access_key) \
  --conf spark.kubernetes.authenticate.driver.serviceAccountName=spark-sa \
  s3a://${S3_BUCKET}/scripts/simple_s3_spark_job.py
```




### Spark operator

#### install spark operator

```
helm repo add spark-operator https://kubeflow.github.io/spark-operator
helm repo update
```

#### install the chart

```
helm install spark-operator spark-operator/spark-operator \
    --namespace spark-operator --create-namespace --wait
```

#### submit job via spark operator

```
kubectl apply -f https://raw.githubusercontent.com/kubeflow/spark-operator/refs/heads/master/examples/spark-pi.yaml
```




## Appendix

### IAM Role for Service Account


spark job with IAM role for service account


create IAM Role for service account 


```
eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve
```



```
eksctl create iamserviceaccount --name spark-sa --namespace $SPARK_NAMESPACE --cluster $CLUSTER_NAME --role-name spark-role \
    --attach-policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --approve
```


