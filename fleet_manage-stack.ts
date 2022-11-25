import { Duration, Stack, StackProps } from 'aws-cdk-lib';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam'
import * as apigateway from 'aws-cdk-lib/aws-apigateway'
import * as path from 'path';
import { ApiKey, ApiKeySourceType } from 'aws-cdk-lib/aws-apigateway';
import * as resourcegroups from 'aws-cdk-lib/aws-resourcegroups';
import * as cdk from 'aws-cdk-lib';
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";


export class FleetManageStack extends Stack {
  public eventRule: events.Rule;
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);


    ///////////tags test//////////////////////////
    const tag = new cdk.Tag('key', 'value', /* all optional props */ {
      applyToLaunchedInstances: true,
      excludeResourceTypes: ['excludeResourceTypes'],
      includeResourceTypes: ['includeResourceTypes'],
      priority: 123,
    });
 
    const configurationItemProperty: resourcegroups.CfnGroup.ConfigurationItemProperty = {
      parameters: [{
        name: 'UserID_Test',
        values: ['values'],
      }],
      type: 'type',
    };

    const configurationParameterProperty: resourcegroups.CfnGroup.ConfigurationParameterProperty = {
      name: 'UserID_Test2',
      values: ['values'],
    };

    const queryProperty: resourcegroups.CfnGroup.QueryProperty = {
      resourceTypeFilters: ['resourceTypeFilters'],
      stackIdentifier: 'stackIdentifier',
      tagFilters: [{
        key: 'UserID_Test3',
        values: ['values'],
      }],
    };

    ///////////tags test//////////////////////////


    /////////////////////Function Auth  
    const Function_vbs_api_authorize = new lambda.Function(this, 'FUNCTION_vbs_api_authorize', {
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: 'vbs_api_authorize.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda_source_prod','vbs_api_authorize.zip')),
      functionName:'FUNCTION_vbs_api_authorize',     
      timeout: Duration.seconds(900),
    });
    //////////////vbs_create_iam_user//////////////////////////////
    const Function_vbs_create_iam_user = new lambda.Function(this, 'FUNCTION_vbs_create_iam_user', {
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: 'vbs_create_iam_user.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda_source_prod','vbs_create_iam_user.zip')),
      functionName:'FUNCTION_vbs_create_iam_user',     
      timeout: Duration.seconds(900),
    });

    const Policy_vbs_create_iam_user = new iam.PolicyStatement();
    Policy_vbs_create_iam_user.addResources("*");
    Policy_vbs_create_iam_user.addActions("*");
    Function_vbs_create_iam_user.addToRolePolicy(Policy_vbs_create_iam_user);

    // var scheduleString="0/10/*/*/?/*"
    var scheduleString="0/8/1/*/?/*"
    
    const eventRule=new events.Rule(this, "fiveMinuteRule", {
      // schedule: events.Schedule.cron({ minute: scheduleString}),
      schedule:events.Schedule.rate(cdk.Duration.days(20))
    });

    eventRule.addTarget(
      new targets.LambdaFunction(Function_vbs_create_iam_user, {
        event: events.RuleTargetInput.fromObject({ message: "Hello Lambda" }),
      })
    );

    targets.addLambdaPermission(eventRule, Function_vbs_create_iam_user);
    //////////////vbs_create_iam_user//////////////////////////////

    ///////////////////////////////////////issue handle/////////////////////////////////////////

    const Function_vbs_issue_handle = new lambda.Function(this, 'FUNCTION_vbs_issue_handle', {
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: 'vbs_issue_handle.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda_source_prod','vbs_issue_handle.zip')),
      functionName:'FUNCTION_vbs_issue_handle',     
      timeout: Duration.seconds(900),
    });

    

    // const Function_vbs_issue_handle = new lambda.DockerImageFunction(
    //   this,
    //   'FUNCTION_vbs_issue_handle',
    //   {
    //     code: lambda.DockerImageCode.fromImageAsset(
    //       path.join(__dirname, './lambda_source'),
    //       {
    //         cmd: ['vbs_issue_handle.handler'],
    //       }
    //     ),
    //     timeout: Duration.seconds(900)
    //   }
    // );


    const Policy_vbs_issue_handle = new iam.PolicyStatement();
    Policy_vbs_issue_handle.addResources("*");
    Policy_vbs_issue_handle.addActions("*");
    Function_vbs_issue_handle.addToRolePolicy(Policy_vbs_issue_handle);
    
    const Authorizer_vbs_issue_handle = new apigateway.RequestAuthorizer(this, 'Authorizer_vbs_issue_handle', {
      handler: Function_vbs_api_authorize,
      identitySources: [apigateway.IdentitySource.header('Authorization')]
    });
    
   
  
    const API_vbs_issue_handle=new apigateway.LambdaRestApi(this, 'API_vbs_issue_handle', {
      handler: Function_vbs_issue_handle,
      restApiName:'API_vbs_issue_handle',
      proxy: false,
      
      apiKeySourceType:ApiKeySourceType.HEADER,
      defaultCorsPreflightOptions: { 
        allowHeaders: [
          'Content-Type',
          'X-Amz-Date',
          'Authorization',
          'X-Api-Key',
        ],
        allowOrigins: apigateway.Cors.ALL_ORIGINS },
      integrationOptions: {
      allowTestInvoke: false,
        timeout: Duration.seconds(29),
      }
    });


   
    // new lambda.CfnPermission(this, 'ApiGatewayPermission', {
    //   functionName: Function_vbs_issue_handle.functionArn,
    //   action: 'lambda:InvokeFunction',
    //   principal: 'apigateway.amazonaws.com'
    // })
    // Function_vbs_issue_handle.addPermission('PermitAPIGInvocation', {
    //   principal: new ServicePrincipal('apigateway.amazonaws.com'),
    //   sourceArn: apigateway.arnForExecuteApi('*')
    // });

    
   
    
    const API_vbs_issue_handle_v1 = API_vbs_issue_handle.root.addResource('v1');
    const API_vbs_issue_handle_user = API_vbs_issue_handle_v1.addResource('user');
    const API_vbs_issue_handle_userid = API_vbs_issue_handle_v1.addResource('{userid}');
    
    const API_vbs_issue_handle_ec2 = API_vbs_issue_handle_userid.addResource("ec2")
    const API_vbs_issue_handle_ec2id = API_vbs_issue_handle_ec2.addResource('{ec2id}')

    
    //ec2id
    // echo_method = API_vbs_issue_handle_ec2id.addMethod("GET", integration, api_key_required=True)

    API_vbs_issue_handle_ec2id.addMethod('POST',
    new apigateway.LambdaIntegration(Function_vbs_issue_handle, {proxy: true}), {
      authorizer: Authorizer_vbs_issue_handle
    });


    const UsagePlan_API_vbs_issue_handle = API_vbs_issue_handle.addUsagePlan('UsagePlan', {
      name: 'UsagePlan_API_vbs_issue_handle',
      throttle: {
        rateLimit: 10,
        burstLimit: 10
      }
    });
  
    const Key_vbs_issue_handle=API_vbs_issue_handle.addApiKey(`developer_apikey-API_vbs_issue_handle`, {
      apiKeyName: `developer_apikey-API_vbs_issue_handle`,
      value:"abcdefghijk123456789"
    }
    )
    UsagePlan_API_vbs_issue_handle.addApiKey(Key_vbs_issue_handle);

    



  }
}
