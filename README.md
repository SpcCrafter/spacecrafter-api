# spacecrafter-api

# Dev env

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Bring up dev environment

1. Build a newest API image
    ```
    make docker-build
    ```
1. Run API and DB containers
    ```
    make dev-env-up
    ```
1. Migrate DB scheme with yoyo-migration
   ```
   make migrate_dev_db
   ```

To check API logs use the following command:
```
docker logs -f spacecrafter-api-api-1
```


Connect to mysql
```
$ docker exec -it spacecrafter-api-db-1 bash
bash-4.4# mysql -udevuser -ppassword
mysql> USE spacecrafter;
mysql> SHOW TABLES;
mysql> DROP TABLE aws_credentials;
```

```
$ curl -X POST -H "Content-Type: application/json" -d '{"username":"yevheniia_p","email":"example@gmail.com","password":"randomPaswd"}' http://127.0.0.1:5050/api/signup
$ curl -X POST -H "Content-Type: application/json" -d '{"username":"yevheniia_p","password":"randomPaswd"}' http://127.0.0.1:5050/api/login
$ curl -H "Authorization: Bearer <GRABBED_NEW_TOKEN>" -X POST -H "Content-Type: application/json" -d '{"aws_access_key_id":"<ACCESS_KEY>","aws_secret_access_key":"<SECRET_ACCESS_KEY>", "preferred_aws_region":"eu-central-1"}' http://localhost:5050/api/aws/credentials
$ curl -H "Authorization: Bearer <GRABBED_NEW_TOKEN>" -X POST -H "Content-Type: application/json" -d  '{"requested_cpu":0.2, "container_name":"test_1", "requested_storage":12}' http://localhost:5050/api/aws/create_container
```


Required IAM policy:

```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"ec2:CreateKeyPair",
				"ec2:DescribeKeyPairs",
				"ec2:DeleteKeyPair",
				"ec2:CreateSecurityGroup",
				"ec2:DescribeSecurityGroups",
				"ec2:DeleteSecurityGroup",
				"ec2:AuthorizeSecurityGroupIngress",
				"ec2:RevokeSecurityGroupIngress",
				"ec2:RunInstances",
				"ec2:DescribeInstances",
				"ec2:TerminateInstances",
				"ec2:DescribeImages",
				"ec2:CreateTags",
				"ec2:DeleteTags",
				"ec2:DescribeTags"
			],
			"Resource": "*"
		},
		{
			"Effect": "Allow",
			"Action": [
				"s3:CreateBucket",
				"s3:PutObject",
				"s3:GetObject",
				"s3:ListBucket"
			],
			"Resource": [
				"arn:aws:s3:::*"
			]
		},
		{
			"Effect": "Allow",
			"Action": [
				"kms:Encrypt",
				"kms:Decrypt",
				"kms:DescribeKey",
				"kms:CreateKey",
				"kms:CreateAlias"
			],
			"Resource": "*"
		}
	]
}

```
