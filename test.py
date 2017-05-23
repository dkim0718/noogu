#!/usr/bin/env python

import os 
import lxml.html

filedir = os.path.expanduser('~/linux_data/raw/whois/')
filelist = os.listdir(filedir) 
textlist = []
for x in filelist:
    with open(filedir+'/'+x,'rb') as f:
        text = f.read()

    try:
        textlist=textlist+lxml.html.fromstring(text).xpath('//*[@id="registrarData" or @id="registryData"]//text()')
    except:
        textlist.append(None)

