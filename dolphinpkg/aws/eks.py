import os
import string
import tempfile
import time
import boto3
import yaml
from flashpkg import utils, logging
from flashpkg.config import config as flash_config
from flashpkg import nsxsmOps
from botocore.exceptions import ClientError, WaiterError
from kubernetes import client, config
from kubernetes.client.rest import ApiException

ADDITIONAL_POLICIES = "additionalPolicies.json"
CLUSTER_IRSA_TEMPLATE = "clusterWithIRSA.tmpl.yaml"
DEFAULT_EKS_VERSION = "13.1"
FAILED_STACK_STATUS = ['CREATE_FAILED', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'DELETE_FAILED', 'CREATE_COMPLETE', 'DELETE_IN_PROGRESS']
ALLSPARK_DEV_ROLENAME = "allspark-dev-role"

RETRY_TIME = 5
RETRY_COUNT = 5


def start(*args, **kwargs):
    cloud = kwargs.get("cloud")
    k8s_version = kwargs.get("version")

    if cloud:
        return __cloud_start(*args, version=k8s_version)

    return __local_start(*args, version=k8s_version)


def cleanup(*args, **kwargs):
    cloud = kwargs.get("cloud")
    if cloud:
        return __cloud_cleanup(*args)

    return __local_cleanup(*args)


def status(*args, **kwargs):
    cloud = kwargs.get("cloud")
    if cloud:
        return __cloud_status(*args)

    return __local_status(*args)


def envsetup(*args, **kwargs):
    cloud = kwargs.get("cloud")
    if cloud:
        return __cloud_envsetup(*args)

    return __local_envsetup(*args)

def __local_start(name, region, zones, instance_type, worker_cnt, auth_mode, networking,
                  iam_role, logging_format, version=DEFAULT_EKS_VERSION):

    output = bool(logging_format)
    log = logging.log(logging_format)
    log_error = logging.log_error(logging_format)

    log("----------------------------------------------------------------------------------------")
    log("Starting cluster in {}, {} with name {}, instance {}, workers {}, auth {}, "
        "networking {}, version {}, iam_roles {}".format(
            region,
            zones,
            name,
            instance_type,
            worker_cnt,
            auth_mode,
            networking,
            version,
            iam_role
        ))
    log("This can take up to 20 minutes to complete")
    log("----------------------------------------------------------------------------------------")

    num_azs = 3
    sts_client = boto3.client('sts')
    ec2_client = boto3.client('ec2', region_name=region)
    launch_user = sts_client.get_caller_identity()['Arn'].split('/')[1]
    eks_zones = str(zones.split(','))
    # Ensure that the cluster launches in >= 2 zones, up to 3
    # If fewer zones are specified in the args, pick additional azs
    if len(eks_zones) < 2:
        possible_zones = [az['ZoneName'] for az in
                          ec2_client.describe_availability_zones()['AvailabilityZones']]
        # avoid duplicates
        for az in eks_zones:
            possible_zones.remove(az)
        log(f'Possible zones {possible_zones}')
        eks_zones += possible_zones[:(num_azs - len(eks_zones))]
        log(f"Using zones {eks_zones} to deploy EKS cluster")

    path, filename = os.path.split(os.path.realpath(__file__))
    file_path = os.path.join(path, CLUSTER_IRSA_TEMPLATE)
    with open(file_path, 'r') as f:
        cluster_tmpl = string.Template(f.read())
    cluster_config = cluster_tmpl.substitute(cluster_name=name, aws_region=region,
                                             nodegroup_name='%s-workers' % name,
                                             version=version,
                                             node_type="auto",
                                             nodes=worker_cnt,
                                             flash_user=launch_user,
                                             zones=eks_zones,
                                             instance_type=instance_type)
    with tempfile.NamedTemporaryFile(mode='w') as f:
        f.write(cluster_config)
        f.flush()
        cmd = 'eksctl create cluster -f %s' % f.name
        (r, out) = utils.command(cmd, streaming=True, lex=True, no_output=output)

    if (r != 0):
        base_error_msg = 'Error when creating EKS cluster\n'
        base_error_msg += "Attempting to delete stale cloudformation stacks associated with the cluster, if any"

        try:
            __delete_cloudformation_stacks(name, logging_format)
        except ClientError as err:
            error_msg = f"AWS Client Error: {err}\n"
            error_msg += "Please use Cloudformation console for more info."
            log_error(error_msg)
            base_error_msg += f'\n{error_msg}'
        except WaiterError as err:
            error_msg = f"AWS Waiter Error: {err}\n"
            error_msg += "Please use Cloudformation console for more info."
            log_error(error_msg)
            base_error_msg += f'\n{error_msg}'

        log_error(base_error_msg)
        return 1

    cnt = 0
    while(True):
        r = status(name, region)
        if (r == 0):
            break
        if (cnt > 120):
            return 1
        time.sleep(10)
        cnt += 1
    context = "%s@%s.%s.eksctl.io" % (launch_user, name, region)

    cnt = 0
    retries_count = 3
    while(True):
        r = update_config(name, region)
        cnt += 1

        if (r == 0):
            break

        if (cnt == retries_count):
            error_msg = "Unable to setup k8s context for EKS cluster"
            log_error(error_msg)
            return 1

    # Add additional IAM policies and insert allspark-dev-role if it exists
    try:

        if iam_role:
            addons(name, iam_role, context, logging_format)
        __authorize_dev_role(cluster_name=name, logging_format=logging_format)
    except ClientError as err:
        if err.response['Error']['Code'] == "NoSuchEntity":
            error_msg = f"Role - '{ALLSPARK_DEV_ROLENAME}' was not found in this account.\n"
            error_msg += f"This role allows other users in the AWS account to access EKS cluster - {name}\n"
            error_msg += f"Please reach out to DevOps team to add {ALLSPARK_DEV_ROLENAME} to your account if the access is needed.\n"
            log_error(error_msg)
            return 0

        error_msg = f"AWS Client Error: \n{err}"
        log_error(error_msg)

        return 1
    return 0

def update_config(name, region):
    cmd = ["aws", "eks", "update-kubeconfig", "--name", name, "--region", region]
    (r, out) = utils.command(cmd)
    return r

def __local_cleanup(name, region, skip_iam, force):
    if not skip_iam:
        r = delete_addon_policy(name)
        if r != 0:
            print("Unable to delete additional policies from worker nodes for cluster {}".format(name))
    cmd = ["eksctl", "delete", "cluster", "--name", name, "--region", region]
    if not force:
        cmd += ["--wait"]
    (r, out) = utils.command(cmd, streaming=True, lex=False)
    if r != 0:
        print("Failed to delete cluster {} in region {}: {}".format(name, region, out))
        print("Attempting to delete stale cloudformation stacks associated with the cluster, if any")
        try:
            __delete_cloudformation_stacks(name)
        except ClientError as err:
            print("AWS Client Error: {}".format(err))
            print("Please use Cloudformation console for more info.")
            return 1
        except WaiterError as err:
            print("AWS Waiter Error: {}".format(err))
            print("Please use Cloudformation console for more info.")
            return 1
        return 0

    ec2 = boto3.resource('ec2', region_name=region, config=utils.AWS_CONFIG)
    volumes = ec2.volumes.filter(Filters=[{
        'Name': 'status',
        'Values': ['available']
    }])
    tag_key = "kubernetes.io/cluster/%s" % (name)
    for volume in volumes or []:
        for tag in volume.tags or []:
            if tag["Key"] == tag_key and tag["Value"] == "owned":
                print("Cleaning up EC2 volume {}".format(volume.id))
                volume.delete()

    return 0


def __cloud_envsetup(name):
    raise Exception("Not implemented")


def __local_envsetup(name, region, logging_format=False):
    cmd = f"aws eks update-kubeconfig --name {name} --region {region}"
    res, _ = utils.command(cmd, streaming=True, lex=False, no_output=bool(logging_format), shell=True)
    if res == 0:
        try:
            username, account, arn = __get_sts_caller()
            if "cloudgate" not in arn:
                credentials = __sts_assume_dev_role()
                if credentials:
                    __patch_awsauth_cm(name, username, arn, bool(logging_format), credentials)
        except ClientError as err:
            if err.response['Error']['Code'] == "NoSuchEntity":
                print("Role - 'allspark-dev-role' was not found in this account - {}".format(account))
                print("Flash has updated context in kubeconfig, but you may not be authorized to access EKS cluster.")
                print("Please reach out to your DevOps team to add 'allspark-dev-role' to your account.")
                return 0
            print("AWS ClientError: \n{}".format(err))
            return 1
        except ApiException as err:
            print("Exception when calling CoreV1Api config_map apis: {}".format(err))
            return 1
    else:
        return res


def __cloud_status(name, region):
    raise Exception("Not implemented")

def __local_status(name, region):
    cmd = ["eksctl", "get", "clusters", name, "--region", region]
    (r, out) = utils.command(cmd)
    return r


def __cloud_start(name, instance_type, worker_cnt, auth_mode,
                  networking, version=DEFAULT_EKS_VERSION):
    raise Exception("Not implemented")


def __cloud_cleanup(name):
    raise Exception("Not implemented")


def get_iam_role(client, stack_name):
    for attempt in range(RETRY_COUNT):
        try:
            stack_res = client.describe_stack_resource(
                StackName=stack_name,
                LogicalResourceId="NodeInstanceRole"
            )

            instance_profile = stack_res['StackResourceDetail']['PhysicalResourceId']
            if not instance_profile:
                print("Unable to determine IAM instance profile for cluster worker nodes")
                print("Retrying...")
                time.sleep(RETRY_TIME)
                continue
            # Right now, it is always the first role within the instance profile
            return instance_profile
        except ClientError as err:
            print("Unable to determine IAM role policy for EKS cluster worker nodes {}".format(err))
            print("Retrying...")
            time.sleep(RETRY_TIME)
            continue
    else:
        print("Max number of retries reached")
        return None


def delete_addon_policy(name):
    stack_name = 'eksctl-%s-nodegroup-%s-workers' % (name, name)
    policy_name = 'additional.workers.%s.eksctl.io' % (name)
    iam_client = boto3.client('iam')
    cf_client = boto3.client('cloudformation')
    try:
        role_name = get_iam_role(cf_client, stack_name)
        if not role_name:
            print("Unable to determine IAM role name for cluster {} worker nodes".format(name))
            return 1
        r = iam_client.list_role_policies(RoleName=role_name)
        if policy_name in r['PolicyNames']:
            print("Cleaning up additional policy from cluster")
            r = iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            print("Successfully deleted additional policy from worker nodes {}".format(r))
            return 0
        else:
            print("No additional IAM policies found for deletion")
            return 0
    except ClientError as err:
        print("Unable to remove worker nodes additional IAM policy: {}".format(err))
        return 1


def addons(name, iam_role, ctx, logging_format=False):
    log = logging.log(logging_format)
    log_error = logging.log_error(logging_format)

    if iam_role:
        stack_name = 'eksctl-%s-nodegroup-%s-workers' % (name, name)
        policy_name = 'additional.workers.%s.eksctl.io' % (name)
        role_name = None
        iam_client = boto3.client('iam')
        cf_client = boto3.client('cloudformation')
        try:
            role_name = get_iam_role(cf_client, stack_name)
            if not role_name:
                log_error("Unable to determine IAM role name for cluster {} worker nodes".format(name))
                return 1
            full_path = os.path.realpath(__file__)
            path, filename = os.path.split(full_path)
            file_path = os.path.join(path, ADDITIONAL_POLICIES)
            with open(file_path, 'r') as f:
                policy_document = f.read()
            r = iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)
            log(f"Successfully updated worker nodes IAM policy {r}")
        except ClientError as err:
            log_error(f"Unable to update worker nodes IAM policy: {err}")
            raise

    addon_path = flash_config.get_ci_build()
    if not addon_path:
        return 0

    if os.path.exists(addon_path) and os.listdir(addon_path):
        cmd = "kubectl --context %s create -f %s" % (ctx, addon_path)
        log('RUNNING:%s' % cmd)
        (r, out) = utils.command(cmd, streaming=True)
        if (r != 0):
            log_error("Error when installing addons: ", cmd)
        return r
    return 0


def __delete_vpc_stack(cfn_client, ec2_client, waiter, stack_name, logging_format=False):
    log = logging.log(logging_format)

    response = cfn_client.describe_stack_resource(
        StackName=stack_name,
        LogicalResourceId='VPC'
    )
    vpc_id = response['StackResourceDetail']['PhysicalResourceId']
    ec2 = boto3.resource('ec2')
    vpc = ec2.Vpc(vpc_id)
    # Delete all gateways associated with the vpc
    for gw in vpc.internet_gateways.all():
        vpc.detach_internet_gateway(InternetGatewayId=gw.id)
        gw.delete()
    # Delete route table associations
    for rt in vpc.route_tables.all():
        if not rt.associations:
            rt.delete()
        for rta in rt.associations:
            if not rta.main:
                rta.delete()
                log("Deleted route table association: {}".format(rta))
    # Delete non-default security groups
    for sg in vpc.security_groups.all():
        if sg.group_name != 'default':
            sg.delete()
            log("Deleted security group: {}".format(sg))
    # Delete non-default network acls
    for acl in vpc.network_acls.all():
        if not acl.is_default:
            acl.delete()
            log("Deleted ACL: {}".format(acl))
    # Delete network interfaces
    for subnet in vpc.subnets.all():
        for interface in subnet.network_interfaces.all():
            interface.delete()
        subnet.delete()
    log("Deleting VPC {}".format(vpc_id))
    ec2_client.delete_vpc(VpcId=vpc_id)
    log("VPC {} is deleted.".format(vpc_id))
    log("Attempting to delete stack: {}".format(stack_name))
    log("This may take upto 15 mins...")
    cfn_client.delete_stack(StackName=stack_name)
    waiter.wait(StackName=stack_name, WaiterConfig={'Delay': 15, 'MaxAttempts': 60})
    log("Successfully deleted stack {}".format(stack_name))

def __delete_associated_elb(cluster_name, logging_format=False):
    log = logging.log(logging_format)

    rgt_client = boto3.client('resourcegroupstaggingapi')
    elb_client = boto3.client('elb')
    response = rgt_client.get_resources(
        TagFilters=[
            {
                'Key': 'kubernetes.io/cluster/{}'.format(cluster_name),
            }
        ],
        ResourceTypeFilters=[
            'elasticloadbalancing:loadbalancer'
        ]
    )
    elb_arns = response['ResourceTagMappingList']
    for elb in elb_arns:
        log("Deleting ELB: {}".format(elb['ResourceARN']))
        elb_name = elb['ResourceARN'].split('/')[-1]
        elb_client.delete_load_balancer(
            LoadBalancerName=elb_name
        )
        log("Loadbalancer {} is deleted".format(elb_name))


def __list_cloudformation_stacks(cluster_name, cfn_client):
    paginator = cfn_client.get_paginator('list_stacks')
    stack_list = []
    page_iterator = paginator.paginate(
        StackStatusFilter=FAILED_STACK_STATUS
    )
    for page in page_iterator:
        for stack in page['StackSummaries']:
            if cluster_name in stack['StackName'] and cluster_name not in stack_list:
                stack_list.append(stack['StackName'])
    return stack_list


def __delete_cloudformation_stacks(cluster_name, logging_format=False):
    log = logging.log(logging_format)

    cfn_client = boto3.client('cloudformation')
    ec2_client = boto3.client('ec2')
    resource_id = None
    waiter = cfn_client.get_waiter('stack_delete_complete')

    # List the stacks whose cluster name tag matches and delete them
    stack_list = __list_cloudformation_stacks(cluster_name, cfn_client)
    if not stack_list:
        log(f"No associated stacks found for cluster {cluster_name} in the state {FAILED_STACK_STATUS}.")
        log("Nothing more to do.")
        return

    # Delete loadbalancers created for the cluster
    __delete_associated_elb(cluster_name, logging_format)

    for stack_name in stack_list:
        log("Attempting to delete stack: {}".format(stack_name))
        if stack_name.endswith('-workers'):
            resource_id = "SG"
        elif stack_name.endswith('-cluster'):
            resource_id = "VPC"
        if resource_id is not None:
            response = cfn_client.describe_stack_resource(
                StackName=stack_name,
                LogicalResourceId=resource_id
            )
            res = response['StackResourceDetail']['PhysicalResourceId']
            response = ec2_client.describe_network_interfaces(
                Filters=[{'Name': 'group-id', 'Values': [res]}, {'Name': 'status', 'Values': ['available']}]
            )
            if response['NetworkInterfaces']:
                nw_interfaceid = response['NetworkInterfaces'][0]['NetworkInterfaceId']
                ec2_client.delete_network_interface(NetworkInterfaceId=nw_interfaceid)
                log("Deleted eni {}".format(nw_interfaceid))
        log("This may take upto 15 mins...")
        try:
            cfn_client.delete_stack(StackName=stack_name)
            waiter.wait(StackName=stack_name, WaiterConfig={'Delay': 15, 'MaxAttempts': 60})
            log("Stack {} is deleted".format(stack_name))
        except WaiterError as err:
            log("Stack deletion timed out. {} \nRetrying stack deletion after deleting VPC".format(err))
            __delete_vpc_stack(cfn_client, ec2_client, waiter, stack_name, logging_format)

def __get_sts_caller():
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    return response['UserId'], response['Account'], response['Arn']


def __get_role_arn(role_name):
    iam_client = boto3.client('iam')
    response = iam_client.get_role(
        RoleName=role_name
    )
    role_arn = response['Role']['Arn']
    return role_arn


def __authorize_dev_role(cluster_name, logging_format):
    username, account, arn = __get_sts_caller()
    if "cloudgate" not in arn:
        role_arn = __get_role_arn(ALLSPARK_DEV_ROLENAME)
        username = ALLSPARK_DEV_ROLENAME.lower()
        __patch_awsauth_cm(cluster_name, username, role_arn, logging_format)


def __sts_assume_dev_role():
    sts_client = boto3.client('sts')
    role_arn = __get_role_arn(ALLSPARK_DEV_ROLENAME)
    assumed_role_object = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='allspark-dev-role-session'
    )
    credentials = assumed_role_object['Credentials']
    return credentials


def __patch_awsauth_cm(cluster_name, username, arn, logging_format=False, credentials=None):
    log = logging.log(logging_format)

    configmap_name = "aws-auth"
    namespace = "kube-system"
    if credentials:
        log(f'Assuming IAM role - {ALLSPARK_DEV_ROLENAME}')
        os.environ['AWS_SECRET_ACCESS_KEY'] = credentials['SecretAccessKey']
        os.environ['AWS_ACCESS_KEY_ID'] = credentials['AccessKeyId']
        os.environ['AWS_SESSION_TOKEN'] = credentials['SessionToken']
    context = nsxsmOps.generate_context(cluster_name, is_eks=True)
    config.load_kube_config(context=context)
    v1_client = client.CoreV1Api()

    existing_cfgmap_obj = v1_client.read_namespaced_config_map(name=configmap_name, namespace=namespace)
    data = existing_cfgmap_obj.data
    api_version = existing_cfgmap_obj.api_version

    log("Allowing user {} to access EKS cluster".format(arn))
    updated_data_body = None
    if "user/" in arn:
        user_list = yaml.safe_load(data['mapUsers'])
        access_policy = {"userarn": "{}".format(arn), "username": "{}".format(username), "groups": ["system:masters"]}
        user_list.append(access_policy) if access_policy not in user_list else log("User already has access")
        updated_data_body = {"mapUsers": yaml.safe_dump(user_list), "mapRoles": data['mapRoles']}
    elif "role/" in arn:
        role_list = yaml.safe_load(data['mapRoles'])
        access_policy = {"rolearn": "{}".format(arn), "username": "{}".format(username), "groups": ["system:masters"]}
        role_list.append(access_policy) if access_policy not in role_list else log("Role already has access")
        updated_data_body = {"mapRoles": yaml.safe_dump(role_list), "mapUsers": data['mapUsers']}
    else:
        log("Unsupported IAM identity in ARN. Valid values are ROLES and USERS")
    if updated_data_body:
        log("Updating aws-auth configmap")
        metadata = client.V1ObjectMeta(name=configmap_name, namespace=namespace)
        updated_cfgmap_obj = client.V1ConfigMap(api_version=api_version, kind="ConfigMap", data=updated_data_body, metadata=metadata)
        v1_client.patch_namespaced_config_map(name=configmap_name, namespace=namespace, body=updated_cfgmap_obj)
        log(f"Successfully patched configMap: {configmap_name}")


def process(arg):
    cloud = arg.get('--cloud')
    if arg['start']:
        return start(
            arg['<name>'], arg['--instance'], arg['--worker'],
            arg['--authorization'], arg['--networking'], cloud=cloud)
    elif arg['cleanup']:
        return cleanup(arg['<name>'], cloud=cloud)
    elif arg['status']:
        return status(arg['<name>'], cloud=cloud)
    elif arg['envsetup']:
        return envsetup(arg['<name>'], cloud=cloud)
