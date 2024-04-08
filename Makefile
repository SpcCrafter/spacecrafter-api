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

docker-clean:
	docker rmi ${IMAGE} &>/dev/null || true

docker-build: docker-clean
  docker build -t $(IMAGE):${VERSION} -f ./dev/Dockerfile

dev-down:
	docker-compose --skip-hostname-check -f ./dev/docker-compose.yml stop

dev-env-up: dev-down
	docker-compose --skip-hostname-check -f ./dev/docker-compose.yml up -d

migrate_dev_db:
	yoyo apply --database 'mysql://devuser:password@127.0.0.1:3306/spacecrafter' ./app/migrations/

lint:
	./app lint