Crossweb
========

A tool for private/public website verification, supporting SSL.


Usage
-----

First, you need two create two files: one will contain, one per line, a
list of internal websites for your target organization.

The other, a list of external websites for your target organization.

The tool will resolve dns for all the external websites, make a list of
unique IP addresses, and for each of those IP addresses, it will test both
http and https access for each of the internal websites.

It will output the title that was found.

From the output (just grep for WARNING, then start reducing) you may find
interesting results.

More details inside the .py file

