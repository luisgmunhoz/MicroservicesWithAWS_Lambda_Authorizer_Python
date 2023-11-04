import json
import os
from typing import Dict, Any
import boto3  # type: ignore
import jwt
from jwt import PyJWK  # type: ignore
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_ID = os.getenv("SECRET_ID")
SECRETS_MANAGER = boto3.client("secretsmanager")


def get_public_key(kid: str) -> PyJWK:
    try:
        # Fetch the secret from AWS Secrets Manager
        secret = SECRETS_MANAGER.get_secret_value(SecretId=SECRET_ID)
        secret_keys = secret.get("SecretString")
        if not secret_keys:
            raise ValueError("Secret keys not found in Secrets Manager")

        # Parse the secret keys
        jwks = json.loads(secret_keys)
        public_key_dict = next(
            (x for x in jwks.get("keys", []) if x.get("kid") == kid), None
        )
        if not public_key_dict:
            raise ValueError(f"Public key not found for kid: {kid}")

        return PyJWK.from_dict(public_key_dict)
    except Exception as e:
        logger.info(f"Error in get_public_key function: {e}")
        raise


def create_policy_document(user_id: str, method_arn: str) -> Dict[str, Any]:
    return {
        "principalId": user_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": method_arn,
                }
            ],
        },
    }


def auth(event: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        # Extract the token from the event
        id_token = event["queryStringParameters"]["token"]

        # Decode the token without verifying the signature
        id_token_details = jwt.decode(  # type: ignore[attr-defined]
            id_token, options={"verify_signature": False}
        )

        # Get the unverified header of the token
        id_token_header = jwt.get_unverified_header(  # type: ignore[attr-defined]
            id_token
        )

        # Extract necessary details from the token
        kid = id_token_header["kid"]
        alg = id_token_header["alg"]
        issuer = id_token_details["iss"]
        audience = id_token_details["aud"]
        user_id = id_token_details["sub"]

        # Create the policy document
        response = create_policy_document(user_id, event["methodArn"])

        # Get the public key
        jwtKey = get_public_key(kid)

        # Decode the token again, this time verifying the signature
        jwt.decode(  # type: ignore[attr-defined]
            id_token, jwtKey.key, algorithms=[alg], issuer=issuer, audience=audience
        )

        # Define the mapping of API groups
        api_group_mapping = {"listadminhotel+": "Admin", "admin+": "Admin"}

        # Determine the expected group based on the event path
        expected_group = next(
            (v for k, v in api_group_mapping.items() if k in event["path"]), None
        )

        # If there is an expected group, check if the user belongs to it
        if expected_group:
            user_group = id_token_details.get("cognito:groups", None)
            if user_group and expected_group not in user_group:
                response["policyDocument"]["Statement"][0]["Effect"] = "Deny"

        return response
    except Exception as e:
        logger.error(f"Error in auth function: {e}")
        return {"statusCode": 500, "body": "Error in auth function"}
