"""pe_asm/data/checkAccessor.py script."""
# !/usr/bin/env python3
# Standard Python Libraries
import logging
import os
import sys
import time

LOGGER = logging.getLogger(__name__)


def checkVMrunning():
    """Connect to the Accessor environment."""
    try:
        kill_screen_ssh()
        vmID = os.getenv("INSTANCE_ID")
        LOGGER.info(vmID)
        checkAWScmd = f"""
            export AWS_DEFAULT_PROFILE=cool-dns-sesmanagesuppressionlist-cyber.dhs.gov &&
            aws ec2 describe-instance-status --instance-ids {vmID}
            """
        # High sev. B605 warning acknowledged
        checkAWS = os.popen(checkAWScmd)  # nosec
        checkAWS = checkAWS.read().split("\n")
        checkAWS = checkAWS[1].split()
        checkAWS = checkAWS[2]
        if checkAWS == "running":
            cmd = "screenConnectAccessor"
            # High sev. B605 warning acknowledged
            os.system(cmd)  # nosec
            LOGGER.info(
                "The accessor was running and screen has been connected. You can now login. "
            )
        else:
            LOGGER.info(
                "The Accessor was not running "
                "and needed to be started."
                " Please wait 2 minutes before "
                "attempting to access Accessor."
            )
            theInstance_ID = os.getenv("INSTANCE_ID")
            cmd = f"""export AWS_DEFAULT_PROFILE=cool-dns-sesmanagesuppressionlist-cyber.dhs.gov &&
                aws ec2 start-instances --instance-ids {theInstance_ID}"""
            # High sev. B605 warning acknowledged
            os.system(cmd)  # nosec
            checkVMrunning()
    except (BrokenPipeError, OSError):
        sys.stderr.close()
        LOGGER.info(f"There was some abnormal operation related to stdout.{sys.stderr}")


def checkCyhyRunning():
    """Connect to Cyhy database."""
    # High sev. B605 warning acknowledged
    cmd = "tocyhy"
    os.system(cmd)  # nosec


def kill_screen_ssh():
    """Kill all ssh connections."""
    # High sev. B605 warning acknowledged
    cmd = "killall ssh"
    os.system(cmd)  # nosec
    time.sleep(1)


def main():
    """Define main function."""
    LOGGER.info("The program is starting...")
    checkVMrunning()


if __name__ == "__main__":
    main()
