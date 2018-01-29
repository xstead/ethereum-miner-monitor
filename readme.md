# Ethereum Miner Monitor

**ethminer** monitoring python application for Linux (Ubuntu 16.04 LTS).

*version v1.0.0*

## Introduction

* This is a **python application** for monitoring linux based **ethereum** miners and keep alive the miner in 24/7. If you have a linux based mining rig, but don't have monitoring system, you can use this standalone script to **keep your miner always running** without manual checks.

* The application is continuously checking the 'ethminer' **process is running** and the current **GPUs utilization** average value.
* Script can **restart** the ethminer, or **reboot** the system.
* **Root** privilege or 'sudoer' user is required, cause the reboot.

* The script doesn't need any extra package/module of python, just pure **python3**. You can use virtualenv too.

* The current version was tested on **Ubuntu 16.04.3 LTS** (xenial), with **GeForce GTX 1070 Ti** cards.

## Leave a Tip

I would be happy about a small donation. Thank you very much.


|   | Currency | Address                                      |
|---|----------|----------------------------------------------|
| Ξ | Ethereum | `0x0079f1B352866Dd7159AA55665e2ccd2482be1B3` |

## Prerequisites

* Installed && configured ethminer - https://github.com/ethereum-mining/ethminer
* Installed python3 - sudo apt-get install python3
* nvidia-smi for NVIDIA Cards
* aticonfig for AMD Cards - **WARNING!** this is not implemented yet

## Usage/Installation

Download or clone the repository.

    user@ubuntu ~ $ 

#### IMPORTANT!
Create your own default configuration file (**config.ini**) and update the values before run python application.

Create **config.ini** based on provided **default**:

    user@ubuntu ~ $ cp config.default config.ini

Edit config, type:

    user@ubuntu ~ $ nano config.ini

Add/edit content:

```ini
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
```


#### WARNING!

Please keep in mind, if you change the **MINER_PROCESS_RESTART_ENABLED** or **MINER_SYSTEM_REBOOT_ENABLED** values to **False**, the script won't work properly. These options are added for **testing purpose only**.

#### Test the script before setup the crontab & double check ouput

    user@ubuntu ~ $ python ethminer_monitor.py


Sample output when miner is running:

    2018-01-29 13:18:37 INFO     [miner-monitor v1.0.0] Current GPU utilization average is 100%.

Sample output when miner is NOT running:

    2018-01-29 13:19:53 INFO     [miner-monitor v1.0.0] [1/5. check] 'ethminer' process is not running, wait 30 sec and check again.
    2018-01-29 13:20:23 INFO     [miner-monitor v1.0.0] [2/5. check] 'ethminer' process is not running, wait 30 sec and check again.
    ...
    ...
    
    2018-01-29 13:22:53 INFO     [miner-monitor v1.0.0] [5/5. check] 'ethminer' process is not running, wait 30 sec and check again.
    2018-01-29 13:22:57 INFO     [miner-monitor v1.0.0] 'ethminer' process is not running, initiate to start.
    2018-01-29 13:22:57 INFO     [miner-monitor v1.0.0] Run sh command: sudo <YOUR CONFIG PATH>/miner.sh >> /var/log/ethereum-miner.log
    2018-01-29 13:23:03 ERROR    [miner-monitor v1.0.0] 'ethminer' Process started successfully.


Sample output when miner is running but GPUs utilization is less then min. level:

    2018-01-29 13:28:35 INFO     [miner-monitor v1.0.0] Current GPU utilization average is 0%.
    2018-01-29 13:28:35 ERROR    [miner-monitor v1.0.0] Current GPU utilization is less than 10%, wait 30 sec and check again.
    2018-01-29 13:28:37 INFO     [miner-monitor v1.0.0] [2/5. check] Current GPU utilization average is 0%.
    ...
    ...
    2018-01-29 13:28:41 ERROR    [miner-monitor v1.0.0] Current GPU utilization is less than 10%, wait 30 sec and check again.
    2018-01-29 13:28:43 INFO     [miner-monitor v1.0.0] [5/5. check] Current GPU utilization average is 0%.
    2018-01-29 13:28:43 ERROR    [miner-monitor v1.0.0] Current GPU utilization is less than 10%, initiate reboot.
    ...


#### If the results test was ok

Create log directory:

    user@ubuntu ~ $ sudo mkdir /var/log/ethminer_monitor/

Edit root crontab:

    user@ubuntu ~ $ sudo crontab -e

Add line, and save:

    */10 * * * * /usr/bin/python3 <YOUR PATH TO SCRIPT>/ethminer_monitor.py >> /var/log/ethminer_monitor/monitor.log

(This will run the script in every 10 minutes. I'm not suggest to make checks within shorter period.)

## Fine tuning

Setup logrotate config:

    user@ubuntu ~ $ sudo nano /etc/logrotate.d/ethminer-monitor

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

    user@ubuntu ~ $ sudo logrotate /etc/logrotate.d/ethminer-monitor --debug

## Todos

* implement **AMD Cards** utilization check
* try to restart ethminer process before reboot the system (soft-reset)
* check ethminer logs parallel with utilization check (Submits && Accepts)