#!/usr/bin/env python3
import os
import logging
import sys

LOGGER = logging.getLogger(__name__)

def checkVMrunning():
    """Connect to the Accessor environment."""
    try:
        vmID = os.getenv("INSTANCE_ID")
        LOGGER.info(vmID)
        checkAWS = os.popen(f'aws ec2 describe-instance-status --instance-ids {vmID}')
        checkAWS = checkAWS.read().split('\n')
        checkAWS = checkAWS[1].split()
        checkAWS = checkAWS[2]
        if checkAWS == 'running':
            os.popen('screenConnectAccessor')
            LOGGER.info('The accessor was running and screen has been connected. You can now login. ')
        else:
            LOGGER.info('The Accessor was not running '
                         'and needed to be started.'
                         ' Please wait 2 minutes before '
                         'attempting to access Accessor.')
            theInstance_ID = os.getenv('INSTANCE_ID')
            os.popen(f'aws ec2 start-instances --instance-ids {theInstance_ID}')
            checkVMrunning()
    except (BrokenPipeError, IOError):
        sys.stderr.close()
        LOGGER.info(f'There was some abnormal operation related to stdout.{sys.stderr}')


def main():
    LOGGER.info('The program is starting...')
    checkVMrunning()


if __name__ == '__main__':
    main()
