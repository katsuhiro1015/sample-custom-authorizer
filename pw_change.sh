#!/bin/sh

user_pool_id=""
client_id=""
user_name=""
password=""
new_password=""

session="$(aws cognito-idp admin-initiate-auth --user-pool-id ${user_pool_id} --client-id ${client_id} --auth-flow ADMIN_NO_SRP_AUTH --auth-parameters USERNAME=${user_name},PASSWORD=${password} | jq -r .Session)"
aws cognito-idp admin-respond-to-auth-challenge --user-pool-id  ${user_pool_id} --client-id ${client_id} --challenge-name NEW_PASSWORD_REQUIRED --challenge-responses USERNAME=${user_name},NEW_PASSWORD=${new_password} --session ${session}
