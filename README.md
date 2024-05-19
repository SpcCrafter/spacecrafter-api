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
    make docker-build
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
$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcxNDMyNDE4NCwianRpIjoiNGQ0NjI5OGUtZmQwMC00ZjAxLWI5ZjAtNGIxMGU2ZDhhZTFlIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InlldmhlbmlpYV9wIiwibmJmIjoxNzE0MzI0MTg0LCJjc3JmIjoiY2ZhOTM5ZDMtZjI2Yy00MzlhLWI2MDEtMGUzZWFjMWQzYWE1IiwiZXhwIjoxNzE0MzI1MDg0fQ.1HkETKTkCL5P9DUskwtVV5qAr7YxO3-BU8EaFZg1Gug" -X POST -H "Content-Type: application/json" -d '{"aws_access_key_id":"<ACCESS_KEY>","aws_secret_access_key":"<SECRET_ACCESS_KEY>", "preferred_aws_region":"eu-central-1"}' http://localhost:5050/api/aws/credentials

{"message":"AWS Credentials stored successfully"}

$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcxNDMyNTEzNSwianRpIjoiOGRjM2I5OGEtNjhhYi00NDQ4LWFkOTYtMDc3YTU5ZmI4ZjgyIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InlldmhlbmlpYV9wIiwibmJmIjoxNzE0MzI1MTM1LCJjc3JmIjoiYjE4ZDEwNTYtYzliNS00NmVjLTk2ZDctYzA0ODhhNjcxOWJmIiwiZXhwIjoxNzE0MzI2MDM1fQ.2ihrzb2WbundnF4C5lSbwZbXL5PPN1Selqs458-JoRQ" -X POST -H "Content-Type: application/json" -d  '{"requested_cpu":0.2,"requested_type":"test", "container_name":"test_1", "requested_storage":12}' http://localhost:5050/api/aws/create_container

{"error":"Unable to find a suitable AMI ID.","message":"Failed to create EC2 instance"}
```
