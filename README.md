While this is a better version of the pyBM CLI, I can't be held liable for interacting with the Bitmessage network.
Bitmessage itself has not been audited, and could possibly be a security nightmare.

PyBitmessage-CLI
===================

Wecome to the **new** and **improved** Command Line Interface for Bitmessage with python 2.

---------

use LGTM for  python code audit:
-------------
https://lgtm.com/projects/g/Lvl4Sword/PyBitmessage-CLI/alerts/?mode=tree&severity=warning

few to no alerts now.

----------

Why recode BM-CLI ?
-------------
To clean up old code and get rid of the places eval() and 'Global' statements were being used. I also placed the code into a class. From there I sorted, cleaned up, and generally spiffied up the place. Here are some other things I've done up to this point:

> Bitmessage no longer needs to be ran in a separate window, and if it it's already running when the CLI is launched, the CLI is closed. Because we can't know if that's from a separate program or not!

> Many try/except are sprinkled throughout the CLI. This is to cover the ConfigParser not being able to find headers, sections, or missing options. Also covers AttributeError, socket.error, and anything else that may occur within the program. Didn't really have that before.
