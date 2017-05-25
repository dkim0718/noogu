# noogu
A simple python WHOIS parser

"Noogu" means "who" in Korean. It is a simple Python parser for WHOIS queries.

Instead of relying too heavily on having too many regexes, noogu tries to 
emulate a person reading actual whois queries. It will try to identify whether
the line currently being read fits under tech, admin, or registrant. Then it
will try to figure out what about the tech/admin/registrant the line is trying
to say (e.g., name, etc)

Usage:
noogu(text)