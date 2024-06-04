import logging
import paramiko
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ContainerService:
    def __init__(self, aws_access_key, aws_secret_key, aws_region=None):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.aws_region = aws_region

    def setup_boto_session(self):
        session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        return session

    def ssh_and_create_container(self, public_ip, key_path, container_params):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #try
        logger.info(f"container params: {container_params}")
        docker_command = f"docker run -d --name {container_params['container_name']}"

        if 'memory' in container_params:
            memory_mb = container_params['memory']
            memory_bytes = memory_mb * (2**20)
            docker_command += f" --memory {memory_bytes}"

        if 'env_vars' in container_params and container_params['env_vars'] is not None:
            for key, value in container_params['env_vars'].items():
                docker_command += f" -e {key}={value}"

        docker_command += f" {container_params['image']}"
        logger.info(f"docker command: {docker_command}")

        ssh.connect(public_ip, username='ubuntu', key_filename=key_path)
        _stdin, stdout, stderr = ssh.exec_command(docker_command)

        stdout_output = stdout.read()
        stderr_output = stderr.read()

        try:
            stdout_output = stdout_output.decode('utf-8')
        except UnicodeDecodeError:
            stdout_output = repr(stdout_output)
            
        try:
            stderr_output = stderr_output.decode('utf-8')
        except UnicodeDecodeError:
            stderr_output = repr(stderr_output)

        if stdout_output:
            logger.info(stdout_output)
        if stderr_output:
            logger.error(stderr_output)

        ssh.close()

        # except Exception as e:
        #     logger.error(f"Failed to create container on instance: {e}")
        #     raise

    def remove_container(self, public_ip, key_path, container_name):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(public_ip, username='ubuntu', key_filename=key_path)
            command = f"docker rm {container_name}"
            _stdin, stdout, stderr = ssh.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                logger.info(f"Container '{container_name}' removed successfully")
            else:
                logger.error(f"Failed to remove container '{container_name}'. Error: {stderr.read().decode('utf-8')}")
        except Exception as e:
            logger.error(f"Failed to remove container '{container_name}': {e}")
        finally:
            ssh.close()
