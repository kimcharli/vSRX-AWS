######################################################################################################################
#  Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance        #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://aws.amazon.com/asl/                                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

from pycfn_custom_resource.lambda_backed import CustomResource
import boto3
from botocore.client import Config
from zipfile import ZipFile
import os
import string
import shutil
import ast
import paramiko
import crypt
import binascii
import logging
import uuid
import urllib2
import json
import datetime
import re

log = logging.getLogger()
log.setLevel(logging.INFO)

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), os.path.join(path, '.')))


# Function to create a CloudWatch Event to invoke the new Lambda Function
def createCWE(FunctName, FunctArn, CWE):
    log.debug("Starting createCWE")
    try:
        cwe = boto3.client('events')
        log.debug("Checking to see if CWE['EventPattern'] exists.")
        if 'EventPattern' in CWE and 'ScheduleExpression' not in CWE:
            log.debug("Only CWE['EventPattern'] exists. Creating Rule!")
            response = cwe.put_rule(
                Name=CWE['RuleName'],
                EventPattern=str(CWE['EventPattern']),
                Description=CWE['Description']
            )
        log.debug("Checking to see if CWE['ScheduleExpression'] exists.")
        if 'EventPattern' not in CWE and 'ScheduleExpression' in CWE:
            log.debug("Only CWE['ScheduleExpression'] exists. Creating Rule!")
            response = cwe.put_rule(
                Name=CWE['RuleName'],
                ScheduleExpression=str(CWE['ScheduleExpression']),
                Description=CWE['Description']
            )
        if 'EventPattern' in CWE and 'ScheduleExpression' in CWE:
            log.debug("Both CWE['EventPattern'] and CWE['ScheduleExpression'] exist. Creating Rule!")
            response = cwe.put_rule(
                Name=CWE['RuleName'],
                ScheduleExpression=str(CWE['ScheduleExpression']),
                EventPattern=str(CWE['EventPattern']),
                Description=CWE['Description']
            )

        log.info("Creating rule: %s", response)
        ruleARN = response['RuleArn']
        log.debug("Adding target %s to rule %s", FunctArn, CWE['RuleName'])
        response = cwe.put_targets(
            Rule=CWE['RuleName'],
            Targets=[
                {
                    'Id': '1',
                    'Arn': FunctArn
                },
            ]
        )
        log.info("Creating target: %s", response)
        funct = boto3.client('lambda')
        try:
            response = funct.remove_permission(FunctionName=FunctName,
                                               StatementId='AWSEvents_' + FunctName + '_' + CWE['RuleName'])
        except Exception as e:
            log.info("Permission doesn't exist")
            response = funct.add_permission(
                FunctionName=FunctName,
                StatementId='AWSEvents_' + FunctName + '_' + CWE['RuleName'],
                Action='lambda:InvokeFunction',
                Principal='events.amazonaws.com',
                SourceArn=ruleARN
            )
            log.info("Add permission: %s", response)
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


# Function to create an S3 bucket event to invoke the new Lambda Function
def createS3Event(FunctName, S3Event):
    try:
        funct = boto3.client('lambda')
        try:
            response = funct.remove_permission(FunctionName=FunctName, StatementId='S3Events_' + FunctName)
        except Exception as e:
            log.info("Permission doesn't exist")

        response = funct.add_permission(
            FunctionName=FunctName,
            StatementId='S3Events_' + FunctName,
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn="arn:aws:s3:::" + S3Event['Bucket']
        )
        s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
        response = s3.put_bucket_notification_configuration(
            Bucket=S3Event['Bucket'],
            NotificationConfiguration=S3Event['EventPattern']
        )
        log.info("Add permission: %s", response)
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def createCustomLambdaFunction(self):
    Bucket, Key = self._resourceproperties.get('LambdaCode').split("/", 1)
    FileName = self._resourceproperties.get('LambdaCode').rsplit("/", 1)[1]
    BucketRegion = self._resourceproperties.get('LambdaCodeRegion')
    Delim = self._resourceproperties.get('Deliminator')
    Region = self._resourceproperties.get('Region')
    FindReplace = self._resourceproperties.get('FindReplace')
    FunctName = self._resourceproperties.get('FunctionName')
    FunctRole = self._resourceproperties.get('Role')
    Runtime = self._resourceproperties.get('Runtime')
    FunctDesc = self._resourceproperties.get('Description')
    Timeout = self._resourceproperties.get('Timeout')
    MemorySize = self._resourceproperties.get('MemorySize')
    VpcConfig = self._resourceproperties.get('VpcConfig')

    FunctHandler = FileName
    FunctHandler = FunctHandler.replace('.py', '')
    FunctHandler = FunctHandler.replace('.zip', '')

    log.info("%s/%s - downloading to /tmp/%s", Bucket, Key, FileName)
    s3 = boto3.client("s3", region_name=BucketRegion)
    tmpdir = '/tmp/lambda_function/'

    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    os.makedirs(tmpdir)

    if os.path.exists('/tmp/lambda.zip'):
        os.remove('/tmp/lambda.zip')

    FilePath = "{}{}".format(tmpdir, FileName)
    s3.download_file(Bucket, Key, FilePath)
    log.info("File downloaded to %s", FilePath)

    if FindReplace is not None:
        funct_code = ''
        log.info("Opening %s", FilePath)
        pythonfile = open(FilePath, 'r')
        log.info("Reading %s", FilePath)
        for line in pythonfile:
            for fr in FindReplace.split(','):
                f, r = fr.split(Delim)
                line = line.replace(f, r)
            funct_code += line
        pythonfile.close()
        log.info("Writing changed file")
        pythonfile = open(FilePath, 'w')
        pythonfile.write(funct_code)
        pythonfile.close()

    if FileName.endswith('.py'):
        log.info("Ziping function .py to /tmp/lambda.zip")
        zipf = ZipFile('/tmp/lambda.zip', 'w')
        zipdir(tmpdir, zipf)
        zipf.close()
        FilePath = '/tmp/lambda.zip'

    funct = boto3.client('lambda')
    log.info("Opening %s", FilePath)
    zipfile = open(FilePath, 'rb')
    log.info("Creating function %s", FileName)
    log.info("Using %s, %s, %s, %s, %s, %s, %s", FunctName, Runtime, FunctRole, FunctHandler + '.lambda_handler',
             FunctDesc, Timeout, MemorySize)
    try:
        if VpcConfig is None:
            log.info("Creating non-VPC function")
            response = funct.create_function(
                FunctionName=FunctName,
                Runtime=Runtime,
                Role=FunctRole,
                Handler=FunctHandler + '.lambda_handler',
                Code={
                    'ZipFile': b'' + zipfile.read()
                },
                Description=FunctDesc,
                Timeout=int(Timeout),
                MemorySize=int(MemorySize),
                Publish=True
            )
        else:
            log.info("Creating function in VPC: %s", VpcConfig)
            VpcConfig = ast.literal_eval(VpcConfig)
            response = funct.create_function(
                FunctionName=FunctName,
                Runtime=Runtime,
                Role=FunctRole,
                Handler=FunctHandler + '.lambda_handler',
                Code={
                    'ZipFile': b'' + zipfile.read()
                },
                Description=FunctDesc,
                Timeout=int(Timeout),
                MemorySize=int(MemorySize),
                VpcConfig=VpcConfig,
                Publish=True
            )
    except Exception as e:
        log.error("Function %s already exists. Error: %s", FunctName, e)
        response = funct.get_function(FunctionName=FunctName)['Configuration']
    zipfile.close()
    return response


def updateCustomLambdaFunction(self):
    Bucket, Key = self._resourceproperties.get('LambdaCode').split("/", 1)
    FileName = self._resourceproperties.get('LambdaCode').rsplit("/", 1)[1]
    Delim = self._resourceproperties.get('Deliminator')
    BucketRegion = self._resourceproperties.get('LambdaCodeRegion')
    Region = self._resourceproperties.get('Region')
    FindReplace = self._resourceproperties.get('FindReplace')
    FunctName = self._resourceproperties.get('FunctionName')
    FunctRole = self._resourceproperties.get('Role')
    Runtime = self._resourceproperties.get('Runtime')
    FunctDesc = self._resourceproperties.get('Description')
    Timeout = self._resourceproperties.get('Timeout')
    MemorySize = self._resourceproperties.get('MemorySize')

    FunctHandler = FileName
    FunctHandler = FunctHandler.replace('.py', '')
    FunctHandler = FunctHandler.replace('.zip', '')

    log.info("%s/%s - downloading to /tmp/%s", Bucket, Key, FileName)
    s3 = boto3.client("s3", region_name=BucketRegion)
    tmpdir = '/tmp/lambda_function/'
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    os.makedirs(tmpdir)
    if os.path.exists('/tmp/lambda.zip'):
        os.remove('/tmp/lambda.zip')
    FilePath = "{}{}".format(tmpdir, FileName)
    s3.download_file(Bucket, Key, FilePath)
    log.info("File downloaded to %s", FilePath)
    if FindReplace is not None:
        funct_code = ''
        log.info("Opening %s", FilePath)
        pythonfile = open(FilePath, 'r')
        log.info("Reading %s", FilePath)
        for line in pythonfile:
            for fr in FindReplace.split(','):
                f, r = fr.split(Delim)
                line = line.replace(f, r)
            funct_code += line
        pythonfile.close()
        log.info("Writing changed file")
        pythonfile = open(FilePath, 'w')
        pythonfile.write(funct_code)
        pythonfile.close()
    if FileName.endswith('.py'):
        log.info("Ziping function .py to /tmp/lambda.zip")
        zipf = ZipFile('/tmp/lambda.zip', 'w')
        zipdir(tmpdir, zipf)
        zipf.close()
    FilePath = '/tmp/lambda.zip'
    funct = boto3.client('lambda')
    log.info("Opening %s", FilePath)
    zipfile = open(FilePath, 'rb')
    log.info("Creating function %s", FileName)
    log.info("Using %s, %s, %s, %s, %s, %s, %s", FunctName, Runtime, FunctRole, FunctHandler + '.lambda_handler',
             FunctDesc, Timeout, MemorySize)
    try:
        log.info("Updating function %s code", FunctName)
        CodeResponse = funct.update_function_code(
            FunctionName=FunctName,
            ZipFile=b'' + zipfile.read(),
            Publish=True
        )
        log.info("Updating function %s configuration", FunctName)
        ConfigResponse = funct.update_function_configuration(
            FunctionName=FunctName,
            Role=FunctRole,
            Handler=Key.rsplit('/')[0].replace('.py', '') + '.lambda_handler',
            Description=FunctDesc,
            Timeout=int(Timeout),
            MemorySize=int(MemorySize)
        )
        log.info("Getting function %s after updates", FunctName)
        response = funct.get_function(FunctionName=FunctName)['Configuration']
    except Exception as e:
        log.error("Function %s update error: %s", FunctName, e)
        log.error("CodeResponse: %s", CodeResponse)
        log.error("ConfigResponse: %s", ConfigResponse)
    zipfile.close()
    return response


def StoreInS3(S3Info):
    try:
        log.debug("Storing all this data in S3: %s.", S3Info)
        for S3Object in S3Info:
            # log.error("Storing requested data in S3: %s.", S3Object)
            s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
            response = s3.put_object(
                Bucket=S3Object['Bucket'],
                Key=S3Object['Key'],
                Body=S3Object['Body'],
                ACL='bucket-owner-full-control',
                ServerSideEncryption='AES256'
            )
            log.info("Data saved to %s/%s", S3Object['Bucket'], S3Object['Key'])
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def StoreInS3KMS(S3Info):
    try:
        log.debug("Storing all this data in S3: %s.", S3Info)
        for S3Object in S3Info:
            # log.debug("Storing requested data in S3: %s.", S3Object)
            s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
            response = s3.put_object(
                Bucket=S3Object['Bucket'],
                Key=S3Object['Key'],
                Body=S3Object['Body'],
                ACL='bucket-owner-full-control',
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=S3Object['SSEKMSKeyId']
            )
            log.info("Data saved to %s/%s", S3Object['Bucket'], S3Object['Key'])
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def StoreInDdb(DdbInfo):
    try:
        log.info("Storing requested data in DDB.")
        ddb = boto3.client('dynamodb')
        response = ddb.put_item(TableName=DdbInfo['TableName'], Item=DdbInfo['Item'])
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def SendAnonymousData(AnonymousData):
    log.info("Sending anonymous data")
    TimeNow = datetime.datetime.utcnow().isoformat()
    TimeStamp = str(TimeNow)
    AnonymousData['TimeStamp'] = TimeStamp
    data = json.dumps(AnonymousData)
    log.info("Data: %s", data)
    url = 'https://metrics.awssolutionsbuilder.com/generic'
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(url, data, headers)
    rsp = urllib2.urlopen(req)
    rspcode = rsp.getcode()
    content = rsp.read()
    log.info("Response from APIGateway: %s, %s", rspcode, content)
    return data


def createRSAkey(bits=1024):
    tmpdir = '/tmp/keys/'
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    os.makedirs(tmpdir)
    k = paramiko.RSAKey.generate(bits)
    k.write_private_key_file(tmpdir + 'key')
    pkeyfile = open(tmpdir + 'key', "r")
    pkey = pkeyfile.read()
    pkeyfile.close()
    os.remove(tmpdir + 'key')
    return pkey, k.get_base64(), k.get_fingerprint()


def createRandomPassword(pwdLength=13, specialChars="True"):
    log.info("Creating random password")
    if specialChars is None:
        specialChars = "True"
    # Generate new random password
    chars = string.ascii_letters + string.digits
    if specialChars == "True":
        chars += '#$%^&+='
        p=re.compile('^(?=.{1,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[#$%^&+=]).*$')
    else:
        p=re.compile('^(?=.{1,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$')
    numTries = 0
    pwdFound = False
    while not pwdFound:
        password = ''
        numTries += 1
        for i in range(int(pwdLength)):
            password += chars[ord(os.urandom(1)) % len(chars)]
        m=p.match(password)
        if m is not None:
            pwdFound = True
    log.info("Password created after %s tries", numTries)
    log.debug("%s", password)
    return password


def createUniqueID():
    log.info("Creating Unique ID")
    # Generate new random Unique ID
    uniqueID = uuid.uuid4()
    log.debug("UUID: %s", uniqueID)
    return uniqueID


def md5hash(value, salt):
    return crypt.crypt(value, '$1$' + salt)


def S3toS3(s3_copy):
    try:
        log.info("Copying S3 Objects")
        source_bucket = s3_copy['SourceBucket']
        destination_bucket = s3_copy['DestinationBucket']
        source_key = s3_copy['SourceS3Key']
        destination_key = s3_copy['DestinationS3Key']
        region = s3_copy['Region']
        s3 = boto3.resource('s3', region_name=region, config=Config(signature_version='s3v4'))
        copy_source = {'Bucket': source_bucket, 'Key': source_key}
        s3.meta.client.copy(copy_source, destination_bucket, destination_key)
    except Exception as e:
        log.error("Exception is: %s", e)


class myCustomResource(CustomResource):
    """Example of how to override the methods for Resource Events"""

    def __init__(self, event):
        super(myCustomResource, self).__init__(event)

    def create(self):
        try:
            LambdaCode = self._resourceproperties.get('LambdaCode')
            FunctName = self._resourceproperties.get('FunctionName')
            FunctArn = self._resourceproperties.get('LambdaArn')
            CWE = self._resourceproperties.get('CloudWatchEvent')
            S3Event = self._resourceproperties.get('S3Event')
            S3Store = self._resourceproperties.get('StoreInS3')
            S3StoreKMS = self._resourceproperties.get('StoreInS3KMS')
            S3toS3Copy = self._resourceproperties.get('S3toS3Copy')
            DdbStore = self._resourceproperties.get('StoreInDDB')
            CreateSshKey = self._resourceproperties.get('CreateSshKey')
            CreateRandomPassword = self._resourceproperties.get('CreateRandomPassword')
            CreateUniqueID = self._resourceproperties.get('CreateUniqueID')
            SendData = self._resourceproperties.get('SendAnonymousData')
            response = None

            if LambdaCode is not None:
                response = createCustomLambdaFunction(self)
                FunctArn = response['FunctionArn']

            if CWE is not None:
                log.debug("Create CWE: %s", CWE)
                CWE = ast.literal_eval(CWE)
                createCWE(FunctName, FunctArn, CWE)

            if S3Event is not None:
                log.debug("Create S3Event: %s", S3Event)
                S3Event = ast.literal_eval(S3Event)
                if FunctArn is not None:
                    S3Event['EventPattern']['LambdaFunctionConfigurations'][0]['LambdaFunctionArn'] = FunctArn
                createS3Event(FunctName, S3Event)

            if S3Store is not None:
                log.debug("Create S3Store: %s", S3Store)
                S3Store = ast.literal_eval(S3Store)
                StoreInS3(S3Store)

            if S3StoreKMS is not None:
                log.debug("Create S3StoreKMS: %s", S3StoreKMS)
                S3StoreKMS = ast.literal_eval(S3StoreKMS)
                StoreInS3KMS(S3StoreKMS)

            if S3toS3Copy is not None:
                log.debug("Copying Data S3 to S3: %s", S3toS3Copy)
                S3toS3Copy = ast.literal_eval(S3toS3Copy)
                S3toS3(S3toS3Copy)

            if DdbStore is not None:
                log.debug("Create DdbStore: %s", DdbStore)
                DdbStore = ast.literal_eval(DdbStore)
                StoreInDdb(DdbStore)

            if SendData is not None:
                log.debug("Sending Data: %s", SendData)
                SendData = ast.literal_eval(SendData)
                SendData['Data'].update({'CFTemplate': 'Created'})
                data = SendAnonymousData(SendData)
                response = {"Status": "SUCCESS", "Data": str(data)}
                log.debug("%s", response)

            if CreateSshKey is not None:
                log.debug("Create SshKey: %s", CreateSshKey)
                prikey, pubkey, fingerprint = createRSAkey()
                CreateSshKey = ast.literal_eval(CreateSshKey)
                # Need logic for if using SSE-KMS
                if CreateSshKey.get('SSEKMSKeyId', '') != '':
                    StoreInS3KMS([{"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PrivateKey'],
                                   "SSEKMSKeyId": CreateSshKey['SSEKMSKeyId'], "Body": prikey},
                                  {"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PublicKey'],
                                   "SSEKMSKeyId": CreateSshKey['SSEKMSKeyId'], "Body": pubkey}])
                else:
                    StoreInS3([{"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PrivateKey'],
                                "Body": prikey},
                               {"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PublicKey'], "Body": pubkey}])
                response = {"Status": "SUCCESS", "MD5": md5hash(prikey, prikey[51:55]), "PubKey": pubkey,
                            "Fingerprint": binascii.hexlify(fingerprint)}

            if CreateRandomPassword is not None:
                # Expect value of CreateRandomPassword to be the desired password length
                password = createRandomPassword(CreateRandomPassword, self._resourceproperties.get('RandomPasswordSpecialCharacters'))
                response = {"Status": "SUCCESS", "Password": password}

            if CreateUniqueID is not None:
                # Value of CreateUniqueID does not matter
                newID = createUniqueID()
                response = {"Status": "SUCCESS", "UUID": str(newID)}
                log.debug("%s", response)

            if response is None:
                response = {"Status": "SUCCESS"}

            # Results dict referenced by GetAtt in template
            return response

        except Exception as e:
            log.error("Create exception: %s", e)
            return {"Status": "FAILED", "Reason": str(e)}

    def update(self):
        try:
            LambdaCode = self._resourceproperties.get('LambdaCode')
            FunctName = self._resourceproperties.get('FunctionName')
            FunctArn = self._resourceproperties.get('LambdaArn')
            CWE = self._resourceproperties.get('CloudWatchEvent')
            S3Event = self._resourceproperties.get('S3Event')
            S3Store = self._resourceproperties.get('StoreInS3')
            DdbStore = self._resourceproperties.get('StoreInDDB')
            SendData = self._resourceproperties.get('SendAnonymousData')

            response = None
            if LambdaCode is not None:
                response = updateCustomLambdaFunction(self)
                FunctArn = response['FunctionArn']

            if CWE is not None:
                CWE = ast.literal_eval(CWE)
                createCWE(FunctName, FunctArn, CWE)

            if S3Event is not None:
                S3Event = ast.literal_eval(S3Event)
                S3Event['EventPattern']['LambdaFunctionConfigurations'][0]['LambdaFunctionArn'] = FunctArn
                createS3Event(FunctName, S3Event)

            if S3Store is not None:
                S3Store = ast.literal_eval(S3Store)
                StoreInS3(S3Store)

            if DdbStore is not None:
                DdbStore = ast.literal_eval(DdbStore)
                StoreInDdb(DdbStore)

            if SendData is not None:
                log.debug("Sending Data: %s", SendData)
                SendData = ast.literal_eval(SendData)
                SendData['Data'].update({'CFTemplate': 'Updated'})
                SendAnonymousData(SendData)
                response = {"Status": "SUCCESS", "Data": str(SendData)}
                log.debug("%s", response)

            if response is None:
                response = {"Status": "SUCCESS"}

            # Results dict referenced by GetAtt in template
            return response

        except Exception as e:
            log.error("Create exception: %s", e)
            return {"Status": "FAILED", "Reason": str(e)}

    # Needs a lot of work to make sure this properly cleans up CWE, S3Events, or stored S3 data!!!
    def delete(self):
        try:
            LambdaCode = self._resourceproperties.get('LambdaCode')
            FunctName = self._resourceproperties.get('FunctionName')
            CWE = self._resourceproperties.get('CloudWatchEvent')
            CreateSshKey = self._resourceproperties.get('CreateSshKey')
            SendData = self._resourceproperties.get('SendAnonymousData')

            log.info("Delete called, cleaning up")

            if SendData is not None:
                log.debug("Sending Data: %s", SendData)
                SendData = ast.literal_eval(SendData)
                SendData['Data'].update({'CFTemplate': 'Deleted'})
                data = SendAnonymousData(SendData)
                response = {"Status": "SUCCESS", "Data": str(data)}
                log.debug("%s", response)

            if LambdaCode is not None:
                funct = boto3.client('lambda')
                log.info("Deleting function %s", FunctName)
                funct.delete_function(FunctionName=FunctName)

            if CWE is not None:
                log.info("Deleting CWE: %s", CWE)
                event = ast.literal_eval(CWE)
                rule = boto3.client('events')
                log.debug("Deleting rule %s.", event['RuleName'])
                targets = rule.list_targets_by_rule(Rule=event['RuleName'])
                log.debug("Rule targets: %s", targets)
                targetIds = []
                for target in targets['Targets']:
                    log.debug("target = %s", target)
                    log.debug("targetId = %s", target['Id'])
                    targetIds.append(str(target['Id']))
                log.debug("Rule target ids: %s", targetIds)
                rule.remove_targets(Rule=event['RuleName'], Ids=targetIds)
                log.debug("Deleting rule: %s", event['RuleName'])
                rule.delete_rule(Name=event['RuleName'])

            if CreateSshKey is not None:
                CreateSshKey = ast.literal_eval(CreateSshKey)
                s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
                s3.delete_object({'Bucket': CreateSshKey['Bucket'], 'Key': CreateSshKey['PrivateKey']})
                s3.delete_object({'Bucket': CreateSshKey['Bucket'], 'Key': CreateSshKey['PublicKey']})

            return {"Status": "SUCCESS"}

        # Delete operations do not return result data
        except Exception as e:
            log.error("Delete exception: %s -- %s", FunctName, e)
            return {"Status": "FAILED", "Reason": str(e)}


def lambda_handler(event, context):
    #print "Lambda Event \n", event
    #print "Lambda Context \n", context
    resource = myCustomResource(event)
    resource.process_event()
    return {'message': 'done'}
