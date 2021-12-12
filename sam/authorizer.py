import requests
import os
import json
import time
import jose
from http import HTTPStatus
from libs.jose import jwk, jwt
from libs.jose.utils import base64url_decode
from auth_util import AuthPolicy

region = 'ap-northeast-1'
client_ids = os.getenv('CLIENT_ID')
user_pool_id = os.getenv('USER_POOL_ID')
ip_white_list = os.getenv('IP_WHITE_LIST').split(',')
# IdTokenの署名に使われた秘密鍵と対になる公開鍵の情報が含まれるエンドポイント
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(
    region, user_pool_id)


def lambda_handler(event, context):
    try:
        token = event['headers']['Authorization']

        tmp = event['methodArn'].split(':')
        awsAccountId = tmp[4]
        apiGatewayArnTmp = tmp[5].split('/')

        policy = AuthPolicy('', awsAccountId)
        policy.restApiId = apiGatewayArnTmp[0]
        policy.region = tmp[3]
        policy.stage = apiGatewayArnTmp[1]

        # Tokenの有効性を確認
        result = is_valid_token(token)
        if result['is_valid_token'] is False:
            # API Gatewayの呼び出しを拒否
            policy.denyAllMethods()
            authResponse = policy.build()
            authResponse['context'] = {
                'message': result['msg']
            }
            return authResponse

        print(json.dumps(event))
        print('IP Address : ' + event['requestContext']['identity']['sourceIp'])
        print('Allow list : ' + ip_white_list[0])
        # IP制限
        if event['requestContext']['identity']['sourceIp'] not in ip_white_list:
            # API Gatewayの呼び出しを拒否
            policy.denyAllMethods()
            authResponse = policy.build()
            authResponse['context'] = {
                'message': result['msg']
            }
            return authResponse

        # API Gatewayの呼び出しを許可
        policy.allowAllMethods()
        authResponse = policy.build()
        authResponse['context'] = {
            'user_id': result['claims']['sub']
        }
        return authResponse

    # JWTのデコードエラーが発生した場合の処理
    except jose.exceptions.JWTError as e:
        policy.denyAllMethods()
        authResponse = policy.build()
        authResponse['context'] = {
            'message': 'JWT error when decoding token'
        }
        return authResponse

    except Exception as e:
        raise e


def is_valid_token(token):
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']

    res_cognito = requests.get(keys_url)

    # エンドポイントが見つからなかった場合の処理
    if res_cognito.status_code != HTTPStatus.OK:
        msg = 'Http request to cognito jwks endpoint failed'
        return {'is_valid_token': False, 'msg': msg, 'claims': None}

    keys = json.loads(res_cognito.text)['keys']

    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    # エンドポイントから公開鍵が見つからなかった場合の処理
    if key_index == -1:
        msg = 'Public key not found in jwks.json'
        return {'is_valid_token': False, 'msg': msg, 'claims': None}

    public_key = jwk.construct(keys[key_index])

    message = str(token).rsplit('.', 1)[0].encode('utf-8')
    encoded_signature = str(token).rsplit('.', 1)[1].encode('utf-8')

    decoded_signature = base64url_decode(encoded_signature)

    # JWTの署名チェックが失敗した場合の処理
    if not public_key.verify(message, decoded_signature):
        msg = 'Signature verification failed'
        return {'is_valid_token': False, 'msg': msg, 'claims': None}

    claims = jwt.get_unverified_claims(token)
    print(json.dumps(claims))
    # JWTの有効期限が切れていた場合の処理
    if time.time() > claims['exp']:
        msg = 'Token is expired'
        return {'is_valid_token': False, 'msg': msg, 'claims': None}
    # audクレームが想定された値でない場合の処理
    # CognitoのJWTのaudクレームには、認証されたユーザーで使用されるclient_idが含まれる
#    if claims['aud'] not in client_ids:
#        msg = 'Token was not issued for this audience'
#        return {'is_valid_token': False, 'msg': msg, 'claims': None}

    return {'is_valid_token': True, 'msg': 'Signature successfully verified', 'claims': claims}
