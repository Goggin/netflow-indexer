#!/usr/bin/env python
import subprocess
from struct import pack

from netflowindexer.base.indexer import BaseIndexer
from netflowindexer.util import serialize_ip

class NFDUMPIndexer(BaseIndexer):
    def get_bytes(self, fn):
        cmd = ["nfdump", "-q", "-6", "-o", "fmt:%sa|%da", "-A", "srcip,dstip", "-a", "-r", fn]
        ips = set()
        add = ips.add
        for line in subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout:
            sa, da = line.decode('utf-8').strip().split('|')
            sa = sa.strip()
            da = da.strip()
            if sa:
                add(serialize_ip(sa))
            if da:
                add(serialize_ip(da))
        return ips
    def fn_to_db(self, fn):
        """turn /data/nfsen/profiles/live/podium/nfcapd.200903011030 into 20090301.db"""
        day = fn[-12:-4]
        return "%s.db" % day

    def fn_to_docid(self, fn):
        """turn /data/nfsen/profiles/live/podium/nfcapd.200903011030 into
                /data/nfsen/profiles/live/podium/nfcapd.2009030110"""
        
        return fn[:-2]

indexer_class = NFDUMPIndexer

