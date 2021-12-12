# Cognito Custom Authorizer

Lambda(Python)でカスタムオーソライザを作成し、Cognitoのユーザプールから払いだされたIdTokenを検証するサンプル

## 参考

https://dev.classmethod.jp/articles/verify_cognit_idtoken_by_apig_custom_auth/


## トークンの取得

```
$ aws cognito-idp admin-initiate-auth --user-pool-id <user_pool_id> --client-id <client_id> --auth-flow ADMIN_NO_SRP_AUTH --auth-parameters USERNAME=<user_name>,PASSWORD=<password>
```

## SAMのデプロイ

```
$ aws cloudformation package --template-file template.yaml --output-template-file output.yaml  --s3-bucket <s3_bucket_name>

$ aws cloudformation deploy --template-file output.yaml --stack-name lambda-authorizer-test --capabilities CAPABILITY_IAM --parameter-overrides UserPoolId=<user_pool_id> ClientId=<client_id> IpWhiteList=<ip_white_list>
```
