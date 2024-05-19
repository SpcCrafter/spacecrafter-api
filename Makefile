IMAGE?=spccrafter_api
VERSION?=dev
TSTAMP?=$(shell date +'%y%m%d%H%M')
export DOCKER_DEFAULT_PLATFORM:=linux/amd64

# Make sed multiplatform....
ifeq ($(shell uname), Darwin)
export SED:=sed -i ''
else
export SED:=sed -i
endif

dev-down:
	docker-compose -f docker-compose-dev.yml down

docker-clean: dev-down
	docker rmi ${IMAGE} &>/dev/null || true

docker-build: docker-clean 
	docker build -t $(IMAGE):$(VERSION) -f Dockerfile.dev .

dev-env-up: dev-down
	docker-compose -f docker-compose-dev.yml up -d

migrate_dev_db:
	yoyo apply --database 'mysql://devuser:password@127.0.0.1:3306/spacecrafter' api/migrations/

lint:
	pylint ./api

test:
	pytest