import json
import boto3
import logging
import boto3
import sys
from datetime import datetime, timedelta,date
from dateutil.relativedelta import relativedelta

from boto3.dynamodb.conditions import Key, Attr

import time
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
AccessControlAllowOrigin="https://d1wzk0972nk23y.cloudfront.net"

def progress_bar(seconds):
    """Shows a simple progress bar in the command window."""
    for _ in range(seconds):
        time.sleep(1)
        print('.', end='')
        sys.stdout.flush()
    print()


def setup(iam_resource):
    """
    Creates a new user with no permissions.
    Creates an access key pair for the user.
    Creates a role with a policy that lets the user assume the role.
    Creates a policy that allows listing Amazon S3 buckets.
    Attaches the policy to the role.
    Creates an inline policy for the user that lets the user assume the role.

    :param iam_resource: A Boto3 AWS Identity and Access Management (IAM) resource
                         that has permissions to create users, roles, and policies
                         in the account.
    :return: The newly created user, user key, and role.
    """
    
    try:
        userName=f'enterpriseUser-{uuid4()}'
        logger.info(userName)
        user = iam_resource.create_user(UserName=userName)
        logger.info("==============user==============")
        logger.info(user)
        print(f"Created user {user.name}.")
    except ClientError as error:
        
        logger.info("==============can't create user==============")
        print(f"Couldn't create a user for the demo. Here's why: "
              f"{error.response['Error']['Message']}")
        raise

    try:
        user_key = user.create_access_key_pair()
        print(f"Created access key pair for user.")
        logger.info("==============user_key==============")
        logger.info(user_key)
    except ClientError as error:
        print(f"Couldn't create access keys for user {user.name}. Here's why: "
              f"{error.response['Error']['Message']}")
        raise
    
    print(f"Wait for user to be ready.", end='')
    progress_bar(10)

    try:
        role = iam_resource.create_role(
            RoleName=f'vbs-role-{uuid4()}',
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'AWS': user.arn},
                    'Action': 'sts:AssumeRole'}]}))
        print(f"Created role {role.name}.")
    except ClientError as error:
        print(f"Couldn't create a role for the demo. Here's why: "
              f"{error.response['Error']['Message']}")
        raise

    try:
        rolepolicy=f'vbs-policy-{uuid4()}'
        policy = iam_resource.create_policy(
            PolicyName=f'vbs-policy-{uuid4()}',
            PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:ListAllMyBuckets',
                    'Resource': 'arn:aws:s3:::*'}]}))
        role.attach_policy(PolicyArn=policy.arn)
        print(f"Created policy {policy.policy_name} and attached it to the role.")
    except ClientError as error:
        print(f"Couldn't create a policy and attach it to role {role.name}. Here's why: "
              f"{error.response['Error']['Message']}")
        raise

    try:
        userpolicy=f'vbs-user-policy-{uuid4()}'
        user.create_policy(
            PolicyName=userpolicy,
            PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Resource': role.arn}]}))
        print(f"Created an inline policy for {user.name} that lets the user assume "
              f"the role.")
    except ClientError as error:
        print(f"Couldn't create an inline policy for user {user.name}. Here's why: "
              f"{error.response['Error']['Message']}")
        raise

    print("Give AWS time to propagate these new resources and connections.", end='')
    progress_bar(10)

    return user, user_key, role,userpolicy,rolepolicy


def show_access_denied_without_role(user_key):
    """
    Shows that listing buckets without first assuming the role is not allowed.

    :param user_key: The key of the user created during setup. This user does not
                     have permission to list buckets in the account.
    """
    print(f"Try to list buckets without first assuming the role.")
    s3_denied_resource = boto3.resource(
        's3', aws_access_key_id=user_key.id, aws_secret_access_key=user_key.secret)
    try:
        for bucket in s3_denied_resource.buckets.all():
            print(bucket.name)
        raise RuntimeError("Expected to get AccessDenied error when listing buckets!")
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDenied':
            print("Attempt to list buckets with no permissions: AccessDenied.")
        else:
            raise
    



def createIAMUser():
    
    iam_resource = boto3.resource('iam')
    user = None
    role = None
    logging.info(iam_resource)
    try:
        logging.info("=-")
        user, user_key, role,userpolicy,rolepolicy = setup(iam_resource)
       
       
    except Exception as e:
        logger.info(e)
    
    finally:
        if user is not None and role is not None:
            # teardown(user, role)
            return user, user_key, role,userpolicy,rolepolicy
        

def lambda_handler(event, context):
    logger.info("==========event=========")
    logger.info(event)
    logger.info("==========context=========")
    logger.info(context)
    try:

        # if ('body' in event.keys()) & ('pathParameters' in event.keys()):
            # userid=event['userid']
            # userpassword=event['userPassword']
           
            # body=event['body']
            # body= json.loads(body)
            
            ## we can verify the id and user password in the future 
            # if (userid!=None)&(userpassword!=None):
        if event!=None:
            if event['action']=='createIAMUser':
                dynamodb = boto3.client('dynamodb')
                dynamodb_resource = boto3.resource('dynamodb', region_name='us-east-1')

                
                table = dynamodb_resource.Table('VBS_Enterprise_Info')
                
            
                response = table.query(
                KeyConditionExpression=Key('UserID').eq('Enterprise_User_Service')
                )

                logger.info("===========db response")
                logger.info(response)
                if 'Items' in response.keys():
                    item = response['Items'][0]

                    if item!=None:
                        if item['awsUserName']!=None:
                            client = boto3.client('iam')
                
                            response_iam = client.list_users()
                            for item2 in response_iam['Users']:
                                if item2['UserName']==item['awsUserName']:
                                    
                                    username=item['awsUserName']
                                    rolename=item['iam_role']
                                    userpolicy=item['userpolicy']
                                    rolepolicy=item['rolepolicy']
                                    
                                    response = client.list_role_policies(
                                            RoleName=rolename,
                                        
                                        )
                                    for item in response['PolicyNames']:
                                        try:
                                            response = client.detach_role_policy(
                                                RoleName=rolename,
                                                PolicyArn=item
                                            )
                                        except Exception as e:
                                            logging.info(e)
                                        try:
                                            response = client.delete_role_policy(
                                                RoleName=rolename,
                                                PolicyName=item
                                            )
                                        except Exception as e:
                                            logging.info(e)
                                        # response = client.delete_policy(
                                        # PolicyArn=item
                                        # )
                                    response = client.list_user_policies(
                                        UserName=username,
                                    
                                        )    
                                    
                                    for item in response['PolicyNames']:
                                        try:
                                            response = client.detach_user_policy(
                                                    UserName=username,
                                                    PolicyArn=item
                                                )
                                        except Exception as e:
                                            logging.info(e)
                                        try:
                                            response = client.delete_role_policy(
                                                    PolicyName=username,
                                                    RoleName=item,
                                                )
                                        except Exception as e:
                                            logging.info(e)
                                            
                                     
                                    try:
                                        response = client.delete_role(
                                            RoleName=rolename
                                        )
                                    except Exception as e:
                                            logging.info(e)
                                    
                                    try:
                                        response = client.delete_user(
                                            UserName=username
                                        )      
                                    except Exception as e:
                                            logging.info(e)
                                    
                                
                                
                                
                            
                            response_2=dynamodb.delete_item(TableName='VBS_Enterprise_Info',Key={'UserID':{'S':'Enterprise_User_Service'}})
                            

                
                
                user, user_key, role,userpolicy,rolepolicy =createIAMUser()
                logger.info(user)
                logger.info(user_key)
                logger.info(role)
                
                if user!=None:
                    # user=response[0] 
                    # user_key=response[1]
                    # role =response[2]
                    

                    response3=dynamodb.put_item(TableName='VBS_Enterprise_Info', Item={
                        'UserID':{'S':'Enterprise_User_Service'},
                        'awsUserName':{'S':str(user_key.user_name)},
                        'keypair_id':{'S':str(user_key.id)},
                        'keypair_secret':{'S':str(user_key.secret)},
                        'iam_role':{'S':str(role.name)},
                        'userpolicy':{'S':str(userpolicy)},
                        'rolepolicy':{'S':str(rolepolicy)},
                        })
                
                                
                alldata=[user, user_key, role,userpolicy,rolepolicy,response3]
                return {
                'headers':{
                    "Access-Control-Allow-Headers" : "Content-Type",
                    "Access-Control-Allow-Origin": AccessControlAllowOrigin,
                    "Access-Control-Allow-Methods": "*"
                },
                'statusCode': 200,
                'body': json.dumps(alldata)
                }
            elif (event['action']=='createTempCredentials'):

                dynamodb_resource = boto3.resource('dynamodb', region_name='us-east-1')

                
                table = dynamodb_resource.Table('VBS_Enterprise_Info')
                
            
                response = table.query(
                KeyConditionExpression=Key('UserID').eq('Enterprise_User_Service')
                )
                if 'Items' in response.keys():
                    item = response['Items'][0]
                    sts_client = boto3.client(
                        'sts', aws_access_key_id=item['keypair_id'], aws_secret_access_key=item['keypair_secret'])
                    try:
                        session_name=f'enterpriseUser_session-{uuid4()}'
                        response = sts_client.assume_role(
                            RoleArn=item['iam_role'], RoleSessionName=session_name)
                        temp_credentials = response['Credentials']
                        logging.info(f"Assumed role {temp_credentials} and got temporary credentials.")
                        return {
                            'headers':{
                                "Access-Control-Allow-Headers" : "Content-Type",
                                "Access-Control-Allow-Origin": AccessControlAllowOrigin,
                                "Access-Control-Allow-Methods": "*"
                            },
                            'statusCode': 200,
                            'body': json.dumps(temp_credentials)
                            }
                      
                    except ClientError as error:
                        logging.info(f"Couldn't assume rol. Here's why: "
                            f"{error.response['Error']['Message']}")
                      
                        
                        raise
                


        
        
        alldata=[{
            "status":'fail',
            "data":"Please check the parameters."
        }]
        return {
                'headers':{
                    "Access-Control-Allow-Headers" : "Content-Type",
                    "Access-Control-Allow-Origin": AccessControlAllowOrigin,
                    "Access-Control-Allow-Methods": "*"
                },
                'statusCode': 401,
                'body': json.dumps(alldata)
                }
    except Exception as e:
        
        logger.info(e)
        json_data = [{
                        "status":"fail",
                            "data":str(e)
                        }]
        return {
            "statusCode": 402,
            "body": json.dumps({"statusCode": 402,"data": json.dumps(json_data)}),
            "isBase64Encoded": False,
            'headers':{
                    "Access-Control-Allow-Headers" : "Content-Type",
                    "Access-Control-Allow-Origin": AccessControlAllowOrigin,
                    "Access-Control-Allow-Methods": "*"
                },
                
            }
   
