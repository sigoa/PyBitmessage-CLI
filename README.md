PyBitmessage-CLI
===================

Wecome to the **new** and **improved** Command Line Interface for Bitmessage!

----------

Why?
-------------
To clean up old code and get rid of the places eval() and 'Global' statements were being used. I also placed the code into a class. From there I sorted, cleaned up, and generally spiffied up the place. Here are some other things I've done up to this point:

> Bitmessage no longer needs to be ran in a separate window, and if it it's already running when the CLI is launched, the CLI is closed. Because we can't know if that's from a separate program or not!

> Many try/except are sprinkled throughout the CLI. This is to cover the ConfigParser not being able to find headers, sections, or missing options. Also covers AttributeError, socket.error, and anything else that may occur within the program. Didn't really have that before.

Help!
-------------

If you require any help at all with specifically the CLI, there are multiple ways to get in contact with me.

> - Lvl4Sword on irc.freenode.net in #bitmessage
> - BM-2cWFLTBnLm3CR9v4jv6FTParrvjumcbdRB via Bitmessage
> - My e-mail which is posted at https://sking.io/contact

----------

Donate
-------------------

Even though it's not necessary, I've been approached by a couple people asking about how they can donate to me. https://sking.io/pay would be the way to do that. Thank you in advance if you do choose to donate :-)!
