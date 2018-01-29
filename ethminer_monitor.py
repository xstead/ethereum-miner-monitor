# -*- coding: utf-8 -*-

# Copyright (c) 2017 by Gábor Németh (gabor.nemeth@xstead.com).
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""

    Ethereum Miner Monitor - v1.0.0
    ==============================================================================================

    Introduction:

        This is a python application for monitoring linux based ethereum miners and keep alive the miner in 24/7.
        If you have a linux based mining rig, but don't have monitoring system, you can use this standalone
        script to keep your miner always running.

        The application is continuously checking the 'ethminer' process is running and the current GPUs
        utilization average value. Script can restart the ethminer, or reboot the system.
        Root privilege or 'sudoer' user is required, cause the reboot.

        The script doesn't need any extra package/module of python, just pure python3. You can use virtualenv too.

        The current version was tested on Ubuntu 16.04.3 LTS (xenial), with GeForce GTX 1070 Ti cards.

    Leave a Tip:

        I would be happy about a small donation. Thank you very much.
        Ethereum Address [ETH]:
        0x0079f1B352866Dd7159AA55665e2ccd2482be1B3

    Prerequisites:

        - Installed && configured ethminer - https://github.com/ethereum-mining/ethminer
        - Installed python3 - sudo apt-get install python3
        - nvidia-smi for NVIDIA Cards
        - aticonfig for AMD Cards ** !! W A R N I N G !! this is not implemented yet

    Usage/Installation:

        !! W A R N I N G !! Please keep in mind, if you change the MINER_PROCESS_RESTART_ENABLED or MINER_SYSTEM_REBOOT_ENABLED
        values to False, the script won't work properly. These options are added for testing purpose only.

        !! I M P O R T A N T !!
        Create a default config and update/set values before run.

        Create config.ini based on provided default:
        cp config.default config.ini

        Edit config:
        nano config.ini
        ------------------------------------------------------
        [DEFAULT]
        MINER_GPUS_TYPE = nvidia

        MINER_PROCESS_RESTART_ENABLED = True
        MINER_SYSTEM_REBOOT_ENABLED = True

        MINER_PROCESS_ID = ethminer
        MINER_START_CMD  = sudo [YOUR PATH THE MINER]/miner.sh >> /var/log/ethereum-miner.log
        MINER_UTILIZATION_CHECK_LOOP = 5
        MINER_UTILIZATION_CHECK_DELAY = 30
        MINER_UTILIZATION_MIN_LEVEL = 10
        MINER_PROCESS_CHECK_LOOP = 5
        MINER_PROCESS_CHECK_DELAY = 30

        EMAIL_NOTIFICATION = False
        EMAIL_MESSAGE = Your server was restarted by miner-monitor.
        EMAIL_SENDER = yoursender@yourdomain.com
        EMAIL_RECIPIENT = yourrecipient@yourdomain.com
        EMAIL_SUBJECT = Server reboot notification

        Test the script before setup the crontab && double check ouput:
        ------------------------------------------------------
        python ethminer_monitor.py


        Sample output when miner is running:
        ------------------------------------------------------
        2018-01-29 13:18:37 INFO     [miner-monitor v1.0.0] Current GPU utilization average is 100%.


        Sample output when miner is NOT running:
        ------------------------------------------------------
        2018-01-29 13:19:53 INFO     [miner-monitor v1.0.0] [1/5. check] 'ethminer' process is not running, wait 30 sec and check again.
        2018-01-29 13:20:23 INFO     [miner-monitor v1.0.0] [2/5. check] 'ethminer' process is not running, wait 30 sec and check again.
        ...
        ...

        2018-01-29 13:22:53 INFO     [miner-monitor v1.0.0] [5/5. check] 'ethminer' process is not running, wait 30 sec and check again.
        2018-01-29 13:22:57 INFO     [miner-monitor v1.0.0] 'ethminer' process is not running, initiate to start.
        2018-01-29 13:22:57 INFO     [miner-monitor v1.0.0] Run sh command: sudo <YOUR CONFIG PATH>/miner.sh >> /var/log/ethereum-miner.log
        2018-01-29 13:23:03 ERROR    [miner-monitor v1.0.0] 'ethminer' Process started successfully.


        Sample output when miner is running but GPUs utilization is less then min. level:
        ------------------------------------------------------
        2018-01-29 13:28:35 INFO     [miner-monitor v1.0.0] Current GPU utilization average is 0%.
        2018-01-29 13:28:35 ERROR    [miner-monitor v1.0.0] Current GPU utilization is less than 10%, wait 30 sec and check again.
        2018-01-29 13:28:37 INFO     [miner-monitor v1.0.0] [2/5. check] Current GPU utilization average is 0%.
        ...
        ...
        2018-01-29 13:28:41 ERROR    [miner-monitor v1.0.0] Current GPU utilization is less than 10%, wait 30 sec and check again.
        2018-01-29 13:28:43 INFO     [miner-monitor v1.0.0] [5/5. check] Current GPU utilization average is 0%.
        2018-01-29 13:28:43 ERROR    [miner-monitor v1.0.0] Current GPU utilization is less than 10%, initiate reboot.
        ...


        If test was ok:
        ------------------------------------------------------
        Create log directory:
        sudo mkdir /var/log/ethminer_monitor/

        Edit root crontab:
        sudo crontab -e

        Add line, and save:
        */10 * * * * /usr/bin/python3 <YOUR PATH TO SCRIPT>/ethminer_monitor.py >> /var/log/ethminer_monitor/monitor.log

        (This will run the script in every 10 minutes. I'm not suggest to make checks within shorter period.)

    Fine tuning:

        Setup logrotate config:
        sudo nano /etc/logrotate.d/ethminer-monitor

        Add these content, and save
        /var/log/ethminer_monitor/*.log {
            weekly
            missingok
            rotate 14
            compress
            notifempty
            sharedscripts
        }

        Finally, test && debug:
        sudo logrotate /etc/logrotate.d/ethminer-monitor --debug

    Todos:

        - implement AMD Cards utilization check
        - try to restart ethminer process before reboot the system (soft-reset)
        - check ethminer logs parallel with utilization check (Submits && Accepts)

"""

import subprocess
import logging
import sys
import time
import os
from statistics import mean
from email.mime.text import MIMEText
import configparser

__version__ = '1.0.0'

class MinerMonitor(object):

    #
    # MinerMonitor initialization
    # --------------------------------------------------------
    def __init__(self):
        """
        class init
        """

        # setup logger
        self.logger = self.setup_logger('miner-monitor')

        # init config file
        app_dir = os.path.dirname(os.path.realpath(__file__))
        self.config_file = os.path.join(app_dir, 'config.ini')

        # load config
        try:
            self.setup_config()
        except Exception as e:
            self.logger.info(e)
            exit(0)

    #
    # load config
    # --------------------------------------------------------
    def setup_config(self):
        """
        Read and load configuration.

        :return: self.cfg
        """
        config = configparser.ConfigParser()
        config.optionxform = str

        try:
            with open(self.config_file) as f:
                config.read_file(f)
        except IOError as e:
            raise ValueError("Error! Can't load the configuration file. {0}".format(e))

        # self config
        self.cfg = {}

        # integer config values
        integer_values = ['MINER_UTILIZATION_CHECK_LOOP', 'MINER_UTILIZATION_CHECK_DELAY',
                          'MINER_PROCESS_CHECK_LOOP', 'MINER_PROCESS_CHECK_DELAY', 'MINER_UTILIZATION_MIN_LEVEL']
        # boolean config values
        boolean_values = ['MINER_PROCESS_RESTART_ENABLED', 'MINER_SYSTEM_REBOOT_ENABLED', 'EMAIL_NOTIFICATION']

        # read config key/value pairs
        for config_key, config_value in config['DEFAULT'].items():
            if config_key in integer_values:
                self.cfg[config_key] = config.getint('DEFAULT', config_key)
            elif config_key in boolean_values:
                self.cfg[config_key] = config.getboolean('DEFAULT', config_key)
            else:
                self.cfg[config_key] = config_value

        # check config values
        if not self.cfg.get('MINER_GPUS_TYPE', None):
            raise ValueError(
                "The 'MINER_GPUS_TYPE' configuration is required. Please update your config.ini file.")
        if not self.cfg.get('MINER_PROCESS_ID', None):
            raise ValueError(
                "The 'MINER_PROCESS_ID' configuration is required. Please update your config.ini file.")
        if not self.cfg.get('MINER_START_CMD', None):
            raise ValueError(
                "The 'MINER_START_CMD' configuration is required. Please update your config.ini file.")

    #
    # check linux system
    # --------------------------------------------------------
    def check_system(self):
        """
        Check must have linux commands are available or not.
        Prevent run monitoring if command is missing.

        :return: ValueError
        """
        if not self.check_command_is_available('nvidia-smi') and self.cfg['MINER_GPUS_TYPE'] in ['nvidia', 'nvidia-amd']:
            raise ValueError("The 'nvidia-smi' command is missing. Please install it before run the ethminer monitor.")
        if not self.check_command_is_available('aticonfig') and self.cfg['MINER_GPUS_TYPE'] in ['amd', 'nvidia-amd']:
            raise ValueError("The 'aticonfig' command is missing. Please install it before run the ethminer monitor.")

    #
    # logger
    # --------------------------------------------------------
    def setup_logger(self, name):
        """
        setup custom log format

        :param name: string
        :return: logger object
        """
        formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s [{0} v{1}] %(message)s'.format(name, __version__),
                                      datefmt='%Y-%m-%d %H:%M:%S')
        screen_handler = logging.StreamHandler(stream=sys.stdout)
        screen_handler.setFormatter(formatter)
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(screen_handler)
        return logger

    #
    # run shell command
    # --------------------------------------------------------
    def run_shell_cmd(self,  shell_cmd, devnull=False ):
        """
        run linux shell command with or without output

        :param shell_cmd: string, linux shell command
        :param devnull: bool - if True -> /dev/null
        :return: subprocess output (STDOUT)
        """
        if devnull:
            null_out = open(os.devnull, 'w')
            output = subprocess.Popen(shell_cmd, shell=True, stdout=null_out)
        else:
            process = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output  = process.stdout.read()
            process.stdout.close()
            process.wait()
        return output

    #
    # linux process check
    # --------------------------------------------------------
    def check_process_is_running(self,  process_id, get_pid=False):
        """
        Check or find process based on process name, with "ps" linux command.

        :param process_id: string, process name
        :param get_pid: bool, if True -> return the process PID or 0
        :return: True, False or PID (int)
        """
        shell_cmd = 'ps -ef | grep "{0}" | grep -v grep  | awk \'{{print $2}}\''.format(process_id)
        output = self.run_shell_cmd(shell_cmd)
        if get_pid:
            pid = 0
            try:
                pid = int(output)
            except:
                pass
            return pid
        else:
            return True if output else False

    #
    # linux check command available
    # --------------------------------------------------------
    def check_command_is_available(self, cmd_to_check):
        """
        Check or find linux command is exists, with cmdline "which ...".

        :param process_id: string, linux command name
        :return: True / False
        """
        shell_cmd = '/usr/bin/which {0}'.format(cmd_to_check)
        output = self.run_shell_cmd(shell_cmd)

        return True if output else False

    #
    # query GPU utilization
    # --------------------------------------------------------
    def query_gpu_utilization(self, gpus_type):
        """
        Query NVIDIA cards current utilization.
        When the RIG (ethminer) is running well, the utilization must be 100%.
        If utilization less then 90%, suspected the card isn't working well or something.

        NVIDIA - timeout 2700 nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits
        AMD - timeout 2700 aticonfig --odgc --adapter=0 | awk '/load/ {print $4}' | cut -d "%" -f1

        !! W A R N I N G !!
        AMD utilization query is not implemented yet.

        :return: int, utilization average
        """

        gpu_utilization_list = None

        if gpus_type == 'nvidia':
            shell_cmd = 'timeout 2700 nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits'
            output = self.run_shell_cmd(shell_cmd).decode('utf-8').strip()
            gpu_utilization_list = output.split('\n')

        if not gpu_utilization_list:
            raise ValueError("Can't get GPU's utilization data. (nvidia-smi or aticonfig is missing ?)")

        try:
            gpu_utilization_list = [int(x) for x in gpu_utilization_list]
        except Exception as e:
            raise ValueError("Utilization result convert to int error. {0}".format(e))

        try:
            return mean(gpu_utilization_list)
        except Exception as e:
            raise ValueError("Average calculation error. {0}".format(e))

    #
    # send email
    # --------------------------------------------------------
    def send_notification(self):
        """
        Try to send email notification when server reboot initiated.

        :return: null
        """
        msg = MIMEText(self.cfg['EMAIL_MESSAGE'])
        msg["From"] = self.cfg['EMAIL_SENDER']
        msg["To"] = self.cfg['EMAIL_RECIPIENT']
        msg["Subject"] = self.cfg['EMAIL_SUBJECT']
        p = subprocess.Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=subprocess.PIPE, universal_newlines=True)
        p.communicate(msg.as_string())

    #
    # restart
    # --------------------------------------------------------
    def restart(self):
        """
        Reboot the server

        :return: null
        """
        command = "/usr/bin/sudo /sbin/shutdown -r now"
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output = process.communicate()[0]

    #
    # process checking loop
    # --------------------------------------------------------
    def check_process_is_running_loop(self):
        """
        Check ethminer is running continuously,
        still loop index is less then 'MINER_PROCESS_CHECK_LOOP'. (default: 5)

        When loop index is greater then max. allowed checking,
        try to start miner with 'MINER_START_CMD'.

        :return: null
        """

        # set base index for checking loop
        check_idx = 1

        # start the checking loop
        while True:

            check_idx += 1
            time.sleep(self.cfg['MINER_PROCESS_CHECK_DELAY'])

            if not self.check_process_is_running(self.cfg['MINER_PROCESS_ID']):

                # stop if index greater then max. allowed
                if check_idx > self.cfg['MINER_PROCESS_CHECK_LOOP']:

                    # show current state
                    self.logger.info("'{0}' process is not running, initiate to start.".format(self.cfg['MINER_PROCESS_ID']))

                    # start miner if not running
                    if self.cfg['MINER_PROCESS_RESTART_ENABLED']:

                        self.logger.info("Run sh command: {0}".format(self.cfg['MINER_START_CMD']))
                        self.run_shell_cmd(self.cfg['MINER_START_CMD'], devnull=True)

                        # wait 5sec after starting
                        time.sleep(5)

                        # show current state
                        if self.check_process_is_running(self.cfg['MINER_PROCESS_ID']):
                            self.logger.info("'{0}' Process started successfully.".format(self.cfg['MINER_PROCESS_ID']))
                        else:
                            self.logger.error("'{0}' Process can't started. Please check your syslog.".format(self.cfg['MINER_PROCESS_ID']))
                    else:
                        # show current state
                        self.logger.warning("'{0}' process RESTART is not enabled!".format(self.cfg['MINER_PROCESS_ID']))

                    # break the loop
                    return False

                self.logger.info("[{2}/{3}. check] '{0}' process is not running, wait {1} sec and check again.".
                                 format(self.cfg['MINER_PROCESS_ID'], self.cfg['MINER_PROCESS_CHECK_DELAY'], check_idx, self.cfg['MINER_PROCESS_CHECK_LOOP']))

            else:
                # break the loop when process is running
                self.logger.info("'{0}' Process is currently running, nothing to do.".format(self.cfg['MINER_PROCESS_ID']))
                return False

    #
    # utilization checking loop
    # --------------------------------------------------------
    def check_utilization_loop(self):
        """
        Check GPU utilization level.

        When everything is running normal (mining operation), just logging the current utilization level,
        usually between 90 - 100 percent.

        When the utilization is less then 'MINER_UTILIZATION_MIN_LEVEL' (default: 10%),
        try to check again 'MINER_UTILIZATION_CHECK_LOOP' (default: 5) times,
        with 'MINER_UTILIZATION_CHECK_DELAY' (default: 30) sec delays.

        When loop index is greater then max. allowed checking 'MINER_UTILIZATION_CHECK_LOOP',
        and utilization is still less then min. level try to reboot the system.

        :return: null
        """

        # set base index for checking loop
        check_idx = 1

        try:

            # start the checking loop
            while True:

                # get utilization level average
                utilization_res = self.query_gpu_utilization(self.cfg['MINER_GPUS_TYPE'])

                # show current state
                if check_idx > 1:
                    self.logger.info("[{1}/{2}. check] Current GPU utilization average is {0}%.".
                                     format(utilization_res, check_idx, self.cfg['MINER_UTILIZATION_CHECK_LOOP']))
                else:
                    # current utilization level
                    self.logger.info("Current GPU utilization average is {0}%.".format(utilization_res))

                if utilization_res <= self.cfg['MINER_UTILIZATION_MIN_LEVEL']:

                    check_idx += 1

                    if check_idx > self.cfg['MINER_UTILIZATION_CHECK_LOOP']:

                        # show current state
                        self.logger.error("Current GPU utilization is less than {0}%, initiate reboot.".
                                          format(self.cfg['MINER_UTILIZATION_MIN_LEVEL']))

                        # start reboot process if enabled
                        if self.cfg['MINER_SYSTEM_REBOOT_ENABLED']:
                            # send email notify
                            if self.cfg['EMAIL_NOTIFICATION'] == True:
                                self.send_notification()

                            # system reboot
                            self.restart()
                        else:
                            # show current state
                            self.logger.warning("System REBOOT is not enabled!")

                        return False
                    else:
                        self.logger.error("Current GPU utilization is less than {1}%, wait {0} sec and check again.".
                                          format(self.cfg['MINER_UTILIZATION_CHECK_DELAY'], self.cfg['MINER_UTILIZATION_MIN_LEVEL']))

                    # force break
                    if check_idx > (self.cfg['MINER_UTILIZATION_CHECK_LOOP']+1):
                        return False

                    time.sleep(self.cfg['MINER_UTILIZATION_CHECK_DELAY'])
                else:
                    return False

        except Exception as e:
            self.logger.error(e)
            exit(0)

    #
    # check miner
    # --------------------------------------------------------
    def check_miner(self):
        """

        MINER_PROCESS_CHECK_LOOP -> 5 times
        MINER_PROCESS_CHECK_DELAY -> 30 sec

        Check 'MINER_PROCESS_ID' is running, if not
        check again 5 times (30sec delay) and try to (re)start the process.


        MINER_UTILIZATION_CHECK_LOOP -> 5 times
        MINER_UTILIZATION_CHECK_DELAY -> 30 sec

        If 'MINER_PROCESS_ID' is running, check the GPU utilization average.
        When average is less then 10%, check again 5 times (30sec delay), and finally
        reboot the system if utilization is still less then 10 percent.

        :return: null
        """
        if not self.check_process_is_running(self.cfg['MINER_PROCESS_ID']):

            self.logger.info(
                "[{2}/{3}. check] '{0}' process is not running, wait {1} sec and check again.".
                    format(self.cfg['MINER_PROCESS_ID'], self.cfg['MINER_PROCESS_CHECK_DELAY'], 1, self.cfg['MINER_PROCESS_CHECK_LOOP']))

            self.check_process_is_running_loop()
        else:
            self.check_utilization_loop()

# endClass::MinerMonitor


#
# main
# --------------------------------------------------------
def main():
    """ run monitoring system """

    # create instance
    miner_monitor = MinerMonitor()

    # check system
    try:
        miner_monitor.check_system()
    except Exception as e:
        miner_monitor.logger.info("System check error: {0}".format(e))
        exit(0)

    # check ethminer
    miner_monitor.check_miner()


if __name__ == '__main__':
    main()
