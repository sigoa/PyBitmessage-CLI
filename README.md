WARNING
===================

While this is a better version of the CLI, I can't be held liable for interacting with the Bitmessage network.
Bitmessage itself has not been audited, and could possibly destroy your computer. Just a heads up!

PyBitmessage-CLI
===================

Wecome to the **new** and **improved** Command Line Interface for Bitmessage!

---------

LGTM
-------------
https://lgtm.com/projects/g/Lvl4Sword/PyBitmessage-CLI/alerts/?mode=tree&severity=warning

Now with only a single issue! (warning that 'label' variable is overused)

----------

Why?
-------------
To clean up old code and get rid of the places eval() and 'Global' statements were being used. I also placed the code into a class. From there I sorted, cleaned up, and generally spiffied up the place. Here are some other things I've done up to this point:

> Bitmessage no longer needs to be ran in a separate window, and if it it's already running when the CLI is launched, the CLI is closed. Because we can't know if that's from a separate program or not!

> Many try/except are sprinkled throughout the CLI. This is to cover the ConfigParser not being able to find headers, sections, or missing options. Also covers AttributeError, socket.error, and anything else that may occur within the program. Didn't really have that before.

Help!
-------------

If you require any help at all with the CLI, please post an issue.

----------
