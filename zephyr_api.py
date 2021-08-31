import os
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import json
import boto3
import bcrypt
from boto3.dynamodb.conditions import Key, Attr
from decimal import *
from time import time
import urllib.parse
import hashlib
import hmac
import uuid
import time
import base64

#setup flask
app = Flask(__name__)
cors = CORS(app, resources = {r"/*": {"origins": "*"}})


dynamodb = boto3.resource('dynamodb')

accounts_table = dynamodb.Table('accounts')
resources_table = dynamodb.Table('resources')
business_accounts_table = dynamodb.Table('businessaccount')


def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

# helper function to grab account details from given email
def get_account_from_db(email):
    resp = accounts_table.query(
        KeyConditionExpression=Key('email').eq(email)
    )

    return resp

# helper function to grab resource details from a given resource_id
def get_resource_from_db(res_id):
    resp = resources_table.query(
        KeyConditionExpression=Key('resource_id').eq(res_id)
    )
    return resp

# helper function that works with get_account_from_db to see if user
# is in database
def check_if_user_in_db(resp):
    if len(resp['Items']) > 0:
        return True
    else:
        return False
# helper function that works with get_resource_from_db to see if user in in db.
def check_if_resource_in_db(resp):
    if len(resp['Items']) > 0:
        return True
    else:
        return False

@app.route('/', strict_slashes = False)
def index():


    response = accounts_table.query(
        KeyConditionExpression=Key('email').eq('shoeasdfstate.edu')

    )

    return("index")



#--------------------------START BUSINESS ACCOUNT TABLE HANDLING SECTION------------
@app.route('/businessaccount', strict_slashes = False, methods = ['POST'])
def post_business_account():
    if request.method == 'POST':

        content = request.get_json(force=True)

        # error, email, username, and password not given in body of request
        if len(content) != 3:
            return(jsonify({"Error": "The request object does not have the 3 required components"}),400)

        # get account from email given in business accounts db
        resp = business_accounts_table.query(
            KeyConditionExpression=Key('email').eq(content['email'])
        )

        # check if email we want to create is already in db

        if len(resp['Items']) > 0:
            return (jsonify({'ERROR': 'This email is already in database.'}),405)


        # Check if the username is already taken
        resp = business_accounts_table.scan(
            FilterExpression=Attr('username').eq(content['username'])
        )
        items = resp['Items']

        if len(items) > 0:
            return (jsonify({"Error": "This username is already taken."}), 404)


        # encrypt password before storing it in db

        # turn password into byte array for encryption
        passwd_in_bytes = str.encode(content['password'])
        salt = bcrypt.gensalt()

        hashedpw = bcrypt.hashpw(passwd_in_bytes, salt)
        hashedpw_string = hashedpw.decode()
        email_addr = content['email']


        # generate a uuid key and store in in account as attr. 'secret_key'.
        secret_key = str(uuid.uuid4())

        # check all user accounts and make sure the uuid isn't already in use... Right now only check once. Ideally needs a while loop
        resp = business_accounts_table.scan(
            FilterExpression=Attr('secret_key').eq(secret_key)
        )
        items = resp['Items']

        while (len(items) > 0):
            secret_key = str(uuid.uuid4())
            resp = business_accounts_table.scan(
                FilterExpression=Attr('secret_key').eq(secret_key)
            )
            items = resp['Items']


        # create new email in database with balance of 0 and no resources
        response = business_accounts_table.put_item(
            Item={
                'email': content['email'],
                'username': content['username'],
                'password': hashedpw_string,
                'secret_key': secret_key,
                'created_resources': []
            }
        )
        return jsonify(response["ResponseMetadata"]["HTTPStatusCode"])

#-------------------------END BUSINESS ACCOUNT TABLE HANDLING SECTION---------------

#--------------------------START RESOURCE TABLE HANDLING SECTION------------------


@app.route('/resource', strict_slashes = False, methods = ['POST', 'GET'])
def post_resource():
    if request.method == 'POST':

        content = request.get_json(force=True)

        # error, resource_id, cost, and dkey not given
        if len(content) != 3:
            return(jsonify({"Error": "The request object does not have the 3 required components"}),400)

        # Get timestamp from the header
        timestamp = request.headers.get('timestamp')

        if not timestamp:
            return (jsonify({'ERROR': 'timestamp not given in request header.'}), 404)

        # get the APP_ID from header
        APP_ID = request.headers.get('APP_ID')

        if not APP_ID:
            return (jsonify({'ERROR': 'APP_ID not given in request header.'}), 404)
        # Get the Nonce from the header
        nonce = request.headers.get('nonce')

        if not nonce:
            return (jsonify({'ERROR': 'nonce not given in request header.'}), 404)

        # Get signature from the header
        signature = request.headers.get('signature')

        if not signature:
            return (jsonify({'ERROR': 'signature not given in request header.'}), 404)


        #check if the time sent is within 2 seconds of the epoch time we get here
        newest_epoch_time = time.time()

        if newest_epoch_time - float(timestamp) > 2:
            return (jsonify({'ERROR': 'The timestamp of the requeset being sent is too old.'}), 404)

        # get business account from app_id
        resp = business_accounts_table.query(
            KeyConditionExpression=Key('email').eq(APP_ID)
        )

        if len(resp['Items']) == 0:
            return (jsonify({'ERROR': 'This account does not exist.'}), 404)

        secret_key = resp['Items'][0]['secret_key']


        # Create HMAC-SHA512 signature using nonce and the business account's
        # secret key.

        sig = hmac.new(secret_key.encode(), nonce.encode(), hashlib.sha512).hexdigest()


        #check if the hash signature given is valid
        if sig != signature:
            return (jsonify({'ERROR': 'The signature sent does not match hash value.'}), 404)
        print("pass!")


        # check if resource is already in database
        resp = get_resource_from_db(content['resource_id'])

        #check if resource we want to create is already in db
        if check_if_resource_in_db(resp):
            return (jsonify({'ERROR': 'This resource id is already in database.'}), 404)


        #create new resource in table with the given information
        response = resources_table.put_item(
            Item = {
                'resource_id': content['resource_id'],
                'cost': Decimal(str(content['cost'])),
                'dkey': content['dkey']
            }
        )

        # append a resource_id to the business account's list of created resources
        resp = business_accounts_table.update_item(
            Key={
                'email': APP_ID
            },
            UpdateExpression="SET created_resources = list_append(created_resources, :i)",
            ExpressionAttributeValues={
                ':i': [content['resource_id']],
            },
            ReturnValues="UPDATED_NEW"
        )

        # return the status code of attempting to post to dynamodb
        return jsonify(response["ResponseMetadata"]["HTTPStatusCode"])


    if request.method == 'GET':
        # get everything in db
        response = resources_table.scan()

        return json.dumps(response['Items'], indent = 2, default = decimal_default)

    else:
        return ('Method not recognized')



@app.route('/resource/<resource_id>', strict_slashes = False, methods = ['GET'])
def get_resource_by_id(resource_id):
    if request.method == 'GET':

        # get the resource
        resp = get_resource_from_db(resource_id)

        # check if resource is in database
        if check_if_resource_in_db(resp) == False:
            return (jsonify({'ERROR': 'This resource does not exist in the database.'}), 404)

        # return the resource's details
        return json.dumps(resp['Items'][0], indent = 2, default = decimal_default)
        #return jsonify(resp['Items'][0])
    else:
        return 'Method not recognized.'

@app.route('/resource/<resource_id>/cost', strict_slashes = False, methods = ['GET', 'PATCH'])
def get_and_patch_resource_cost(resource_id):
    if request.method == 'GET':

        # get the resource
        resp = get_resource_from_db(resource_id)
        # check if resource is in database
        if check_if_resource_in_db(resp) == False:
            return (jsonify({'ERROR': 'This resource does not exist in the database.'}),404)

        #return jsonify(resp['Items'][0]['cost'])
        return json.dumps(resp['Items'][0]['cost'], indent = 2, default = decimal_default)
    elif request.method == 'PATCH':
        content = request.get_json(force=True)

        # get the resource
        resp = get_resource_from_db(resource_id)
        # check if resource is in database
        if check_if_resource_in_db(resp) == False:
            return (jsonify({'ERROR': 'This resource does not exist in the database.'}),404)

        #dynamodb update the cost attribute
        resp = resources_table.update_item(
            Key = {
                'resource_id': resource_id
                },
            UpdateExpression="SET cost = :c",
            ExpressionAttributeValues={
                ':c': Decimal(str(content['cost']))
                },
            ReturnValues="UPDATED_NEW"
        )

        return jsonify(resp["ResponseMetadata"]["HTTPStatusCode"])

    else:
        return 'Method not recognized.'

@app.route('/resource/<resource_id>/dkey', strict_slashes = False, methods = ['GET', 'PATCH'])
def get_and_patch_resource_dkey(resource_id):
    if request.method == 'GET':

        # get the resource
        resp = get_resource_from_db(resource_id)
        # check if resource is in database
        if check_if_resource_in_db(resp) == False:
            return (jsonify({'ERROR': 'This resource does not exist in the database.'}),404)
        return json.dumps(resp['Items'][0]['dkey'], indent = 2, default = decimal_default)

    elif request.method == 'PATCH':
        content = request.get_json(force=True)

        # get the resource
        resp = get_resource_from_db(resource_id)
        # check if resource is in database
        if check_if_resource_in_db(resp) == False:
            return (jsonify({'ERROR': 'This resource does not exist in the database.'}),404)

        #dynamodb update the cost attribute
        resp = resources_table.update_item(
            Key = {
                'resource_id': resource_id
                },
            UpdateExpression="SET dkey = :d",
            ExpressionAttributeValues={
                ':d': content['dkey']
                },
            ReturnValues="UPDATED_NEW"
        )

        return jsonify(resp["ResponseMetadata"]["HTTPStatusCode"])


#--------------------------END RESOURCE TABLE HANDLING SECTION----------------
# ---------------------------- START ACCOUNT TABLE HANDLING SECTION ----------------------------------------------


@app.route('/confirmtransaction/email/<email>/resource/<resource_id>', strict_slashes = False, methods = ['POST', 'GET'])
def confirmtransaction(email,resource_id):
    if request.method == 'POST':
        # get account from email given in db
        resp = get_account_from_db(email)
        db_resp = get_resource_from_db(resource_id)

        # check if user is in db
        if not check_if_user_in_db(resp):
            return (jsonify({'ERROR': 'This email does not exist.'}),400)

        # check if resource is in database
        if check_if_resource_in_db(db_resp) == False:
            return (jsonify({'ERROR': 'This resource does not exist in the database.'}), 400)


        # check if user owns content already
        for item in resp['Items'][0]['resources']:
            if item == resource_id:
                return(jsonify({"Error": "The user already owns this resource"}),400)

        # if buying piece of content does not put the user in debt of
        # -$25 or greater, let them buy it.
        curr_balance = resp['Items'][0]['balance']
        resource_cost = db_resp['Items'][0]['cost']
        if curr_balance - resource_cost < -25:
            return (jsonify({'ERROR': 'Purchasing this will give the user a debt greater than $25. Must add more funds to purchase this resource.'}), 404)

        # append a resource_id to the user's list of resources
        resp = accounts_table.update_item(
            Key={
                'email': email
            },
            UpdateExpression="SET resources = list_append(resources, :i)",
            ExpressionAttributeValues={
                ':i': [resource_id],
            },
            ReturnValues="UPDATED_NEW"
        )

        #update user's account_balance
        resp = accounts_table.update_item(
            Key = {
                'email': email
                },
            UpdateExpression="SET balance = :b",
            ExpressionAttributeValues={
                ':b': (curr_balance - resource_cost)
                },
            ReturnValues="UPDATED_NEW"
        )


        return jsonify(resp['ResponseMetadata']['HTTPStatusCode'])

@app.route('/useraccount', strict_slashes = False, methods = ['POST', 'GET'])
def account_email():
    if request.method == 'POST':

        content = request.get_json(force=True)

        # error, email, username, and password not given in body of request
        if len(content) != 3:
            return(jsonify({"Error": "The request object does not have the 3 required components"}),400)

        # get account from email given in db
        resp = get_account_from_db(content['email'])

        # check if email we want to create is already in db
        if check_if_user_in_db(resp):
            return (jsonify({'ERROR': 'This email is already in database.'}),405)

        # Check if the username is already taken
        resp = accounts_table.scan(
            FilterExpression=Attr('username').eq(content['username'])
        )
        items = resp['Items']

        if len(items) > 0:
            return (jsonify({"Error": "This username is already taken."}), 404)


        # encrypt password before storing it in db

        # turn password into byte array for encryption
        passwd_in_bytes = str.encode(content['password'])
        salt = bcrypt.gensalt()

        hashedpw = bcrypt.hashpw(passwd_in_bytes, salt)
        hashedpw_string = hashedpw.decode()


        # generate hmacsha512 key and store in in account as attr. 'secret_key'.

        # create new email in database with balance of 0 and no resources
        response = accounts_table.put_item(
            Item={
                'email': content['email'],
                'username': content['username'],
                'password': hashedpw_string,
                'balance': 0,
                'resources': []
            }
        )
        return jsonify(response["ResponseMetadata"]["HTTPStatusCode"])

    elif request.method == 'GET':
        # get everything in db
        response = accounts_table.scan()


        #print(jsonify(response['Items'], indent = 2, default = decimal_default))
        return json.dumps(response['Items'], indent = 2, default = decimal_default)

    else:
        return ('Method not recognized')

@app.route('/useraccount/login/username/<username>/password/<password>', strict_slashes = False, methods = ['GET'])
def user_login(username, password):
    if request.method == 'GET':

        # Get all accounts in db, and filter by username equal to the one
        # given in the URL.
        resp = accounts_table.scan(
            FilterExpression=Attr('username').eq(username)
        )
        items = resp['Items']

        # Check if this user is in the database
        if len(items) == 0:
            return (jsonify({"FAIL": "This username does not exist."}), 404)

        # Get the password from the database
        password_string = items[0]['password']

        if bcrypt.checkpw(password.encode(),password_string.encode()):
            return json.dumps(items[0], indent = 2, default = decimal_default)
        else:
            return (jsonify({"Fail":"Passwords do not match"}), 404)



@app.route('/useraccount/<email>', strict_slashes = False, methods = ['GET'])
def get_specific_account(email):
    if request.method=='GET':
        # get the user
        resp = get_account_from_db(email)

        # check if user is in database
        if check_if_user_in_db(resp) == False:
            return (jsonify({'ERROR': 'This email does not exist in the database.'}), 404)

        # return the user's details
        return json.dumps(resp['Items'][0], indent = 2, default = decimal_default)
        #return jsonify(resp['Items'][0])
    else:
        return 'Method not recognized.'

@app.route('/useraccount/<email>/balance', strict_slashes = False, methods=['GET', 'PATCH'])
def account_balance(email):
    if request.method == 'GET':

        # get the user
        resp = get_account_from_db(email)

        # check if user is in database
        if check_if_user_in_db(resp) == False:
            return (jsonify({'ERROR': 'This email does not exist in the database.'}), 404)

        return json.dumps(resp['Items'][0]['balance'], indent = 2, default = decimal_default)
        #return jsonify(resp['Items'][0]['balance'])

    elif request.method == 'PATCH':
        # get data from the HTTP request's body
        content = request.get_json(force=True)

        #error, email not given in body of request
        if len(content) != 1:
            return(jsonify({"Error": "The request object does not have a new balance given"}),400)

        # check if the email given is in the db
        resp = get_account_from_db(email)

        #check if user exists in db
        if check_if_user_in_db(resp) == False:
            return (jsonify({'ERROR': 'This email does not exist in the database.'}), 404)

        # set the balance to the value given in the HTTP request body
        resp = accounts_table.update_item(
            Key = {
                'email': email
                },
            UpdateExpression="SET balance = :b",
            ExpressionAttributeValues={
                ':b': content['balance']
                },
            ReturnValues="UPDATED_NEW"
        )
        return jsonify(resp["ResponseMetadata"]["HTTPStatusCode"])

    else:
        return 'Method not recognized'

@app.route('/useraccount/<email>/resources', strict_slashes = False, methods = ['PATCH', 'GET'])
def account_resources(email):
    if request.method == 'GET':

        # get the user
        resp = get_account_from_db(email)

        # check if user is in database
        if check_if_user_in_db(resp) == False:
            return (jsonify({'ERROR': 'This email does not exist in the database.'}), 404)

        # return list of resources associated with the user we looked up
        return json.dumps(resp['Items'][0]['resources'], indent = 2, default = decimal_default)
        #return jsonify(resp['Items'][0]['resources'])

    elif request.method == 'PATCH':

        # get data from the HTTP request's body
        content = request.get_json(force=True)

        #error, email not given in body of request
        if len(content) != 1:
            return(jsonify({"Error": "The request object does not have a resource id given"}),400)

        # get the user
        resp = get_account_from_db(email)

        # check if user is in database
        if check_if_user_in_db(resp) == False:
            return (jsonify({'ERROR': 'This email does not exist in the database.'}), 404)

        # check if the user already has the resource in their list
        for item in resp['Items'][0]['resources']:
            if item == content['resource_id']:
                return(jsonify({"Error": "The user already owns this resource"}),400)

        # append a resource_id to the user's list of resources
        resp = accounts_table.update_item(
            Key={
                'email': email
            },
            UpdateExpression="SET resources = list_append(resources, :i)",
            ExpressionAttributeValues={
                ':i': [content['resource_id']],
            },
            ReturnValues="UPDATED_NEW"
        )

        return jsonify(resp['ResponseMetadata']['HTTPStatusCode'])

    else:
        return 'Method not recognized'


    # ----------------------------END ACCOUNT TABLE HANDLING SECTION --------------------------


if __name__ == '__main__':
    #app.run(host='127.0.0.1', port=8080, debug=True)
    app.run(host='0.0.0.0', port=8080, debug=True)
