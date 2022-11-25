import json
import boto3
import logging
import boto3
import sys
from datetime import datetime, timedelta,date
from dateutil.relativedelta import relativedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)
def lambda_handler(event, context):
    logger.info(event)
    
    try:
        if 'body' in event.keys():
            
            body=event['body']
            body= json.loads(body)
            
            # if ('ec2ids' in body.keys())&('regions' in body.keys()):
            # if True:
            if "ec2id" in body.keys() & "region" in body.keys() & "action" in body.keys():
                client = boto3.client('ssm')
                ssm = boto3.client('ssm' )
                payload={
                    'action':'createTempCredentials'
                }
                result = client.invoke(FunctionName="FUNCTION_vbs_create_iam_user",
                    InvocationType='RequestResponse',                                      
                    Payload=json.dumps(payload))


                session=boto3.session.Session(
                    region_name='us-east-1',
                aws_access_key_id="AKIA2KYYYP7MX4X5BRQ7",
                aws_secret_access_key="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")
                ssm_client=session.client('ssm')
                instanceId=body['ec2id']
                region=body['region']

                if body['action']=='CollectLogs':
                    testCommand = ssm_client.send_command( 
                        InstanceIds=[instanceId], 
                        DocumentName='AWSSupport-RunEC2RescueForWindowsTool', 
                        Comment=instanceId+'_rescue', 
                        OutputS3BucketName='vbs-tempfile-bucket-htc', 
                        OutputS3KeyPrefix=instanceId+'/CollectLogs', 
                        Parameters={ 
                            "commands":[ 
                                "CollectLogs"
                                ]  
                            
                        } )
                                
                alldata=[{
                        "status":'success',
                        "ec2id":"None",
                        "data":body
                    }]
                return {
                'headers':{
                    "Access-Control-Allow-Headers" : "Content-Type",
                    "Access-Control-Allow-Origin": "http://vbs-user-website-bucket.s3-website-us-east-1.amazonaws.com",
                    "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
                },
                'statusCode': 200,
                'body': json.dumps(alldata)
                }
        
        
        alldata=[{
            "status":'fail',
            "data":"Please check the parameters."
        }]
        return {
                'headers':{
                    "Access-Control-Allow-Headers" : "Content-Type",
                    "Access-Control-Allow-Origin": "https://d1wzk0972nk23y.cloudfront.net",
                    "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
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
                    "Access-Control-Allow-Origin": "https://d1wzk0972nk23y.cloudfront.net",
                    "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
                },
                
            }
   
