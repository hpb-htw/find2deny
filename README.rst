*********
find2deny
*********


Tools to build Firewall Command for UFW from List of (Apache)-Log-files.

It creates a file `block-ip.sh` which contains Linux UWF-Command to block IP-network, but it
does not change any Firewall-rules on your computer.


Installation
============

To install the latest release on `PyPI <https://pypi.org/project/find2deny/>`_,
simply run:

::

  pip install find2deny

Or to install the latest development version, run:

::

  git clone [TODO]
  cd find2deny
  python setup.py install


Quick Tutorial
==============

For example, you have a set of Apache Log-files in a directory ``apache2`` like

* ``access.log``
* ``access.log.1``,
* ``access.log.2.gz``,
* ...


The python script ``find2deny-cli`` can create a shell-Script ``block-ip.sh`` which contains commands like

::

    #!/bin/bash
    ufw deny from 1.2.3.4/0 to any
    ufw deny from 1.2.3.4/1 to any
    ...



1. Make a Configuration-File: Simple copy this configuration to a file, say ``config.toml``::

        verbosity = "INFO"
        # Path to apache log files in system
        log_files = ["apache2/access.log.*"]
        # Log Pattern
        log_pattern = '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'
        # temporary sqlite database
        database_path="./blocked-ip.sqlite"


        [[judgment]]
            name = "path-based-judgment"
            [judgment.rules]
                bot_request = [
                    "/?XDEBUG_SESSION_START=phpstorm",
                    "/phpMyAdmin/",
                    "/pma/",
                    "/myadmin/",
                    "/MyAdmin/",
                    "/mahua/",
                    "/wp-login",
                    "/webdav/",
                    "/help.php",
                    "/java.php",
                    "/db_pma.php",
                    "/logon.php",
                    "/help-e.php",
                    "/hell.php",
                    "/defect.php",
                    "/webslee.php",
                    "http://www.123cha.com/",
                    "http://www.wujieliulan.com/",
                    "http://www.epochtimes.com/",
                    "http://www.ip.cn/",
                    "www.baidu.com:443"
                ]

        [[judgment]]
            name = "time-based-judgment"
            [judgment.rules]
                max_request = 501
                interval_seconds = 10


        [[execution]]
            name = "ufw_cmd_script"
            [execution.rules]
                script = "./block-ip.sh"


2. Run script::

        find2deny-init-db blocked-ip.sqlite

   to create a Sqlite-Database in file ``blocked-ip.sqlite``. The filename must match the configuration
   ``database_path`` in the file ``config.toml``.

3. Run::

        find2deny-cli config.toml


   to create file ``block-ip.sh``. Then you can examinate the file ``block-ip.sh`` and run it from your shell
   to update your firewall.



Configuration
=============

The syntax used in configuration file ist `Toml <https://github.com/toml-lang/toml>`_. There are three
sections in a configuration files, as you see above

Common Configuration
--------------------
This section defines common configurations, such as how much infos should be printed onto console, ect.


Judgment
--------
This section defines a list of Judgments. They are identified by name. At this time there are only two
judments: ``path-based-judgment`` and ``time-based-judgment``. Each judgment has its owns configuration.

Judgments are classes, which use rules defined in configuration to decide which IPs should be blocked.
They extend the class ``AbstractIpJudgment``.


Execution
---------

This section defines a list of executions. At this time there is only one execution. Executions are classes
which create firewall-rules or execute something, which nessesary to block an IP, or , in this implementation,
block the network, to which the ip belongs.



