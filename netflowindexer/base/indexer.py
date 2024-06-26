#!/usr/bin/env python
import os
import sys
import xapian
import itertools
import time

from netflowindexer.util import serialize_ip

class BaseIndexer:
    def __init__(self, cfg_data):
        self.database = None
        self.db_fn = None
        self.dirty = False
        self.doc_count = 0
        self.cfg_data = cfg_data
        self.out_dir = cfg_data['dbpath']
        self.flowpath = cfg_data['flowpath']

    def has_document(self, key):
        enquire = xapian.Enquire(self.database)
        query = xapian.Query(key)

        enquire.set_query(query)
        matches = enquire.get_mset(0, 2)

        for match in matches:
            return True
        return False

    def get_ips(self, fn):
        raise NotImplementedError()

    def get_bytes(self, fn):
        ips = self.get_ips(fn)
        bytes = list(map(serialize_ip, ips))
        return [_f for _f in bytes if _f]

    def fn_to_db(self, fn):
        """turn /data/nfsen/profiles/live/podium/nfcapd.200903011030 into 20090301.db"""
        raise NotImplementedError()

    def fn_to_docid(self, fn):
        """turn /data/nfsen/profiles/live/podium/nfcapd.200903011030 into
                /data/nfsen/profiles/live/podium/nfcapd.2009030110"""
        raise NotImplementedError()

    def open_db(self, fn):
        db_fn = os.path.join(self.out_dir, self.fn_to_db(fn))
        if db_fn != self.db_fn:
            self.flush()
            self.database = xapian.WritableDatabase(db_fn, xapian.DB_CREATE_OR_OPEN)
            self.db_fn = db_fn
        return self.database

    def flush(self):
        if not self.database:
            return
        if not self.dirty:
            return
        self.dirty = False
        st = time.time()
        self.database.flush()
        print("Flush took %0.1f seconds." % (time.time() - st))
        sys.stdout.flush()

    def maybe_flush(self):
        self.doc_count += 1
        if self.doc_count == 12*3:
            self.doc_count = 0
            self.flush()

    def index_files(self, fns):
        for docid, files in itertools.groupby(fns, self.fn_to_docid):
            #print '*', docid
            self.real_index_files(list(files))
        self.flush()

    def real_index_files(self, fns):
        #begin = time.time()
        last_fn = fns[-1]
        database = self.open_db(last_fn)

        unindexed_fns = [fn for fn in fns if not self.has_document("fn:%s" % fn)]
        # If all of the files are already indexed, nothing to do
        if len(unindexed_fns) == 0:
            return
        if len(unindexed_fns) == 1:
            st = time.time()
            ips = self.get_bytes(unindexed_fns[0])
            print("read %s in %0.1f seconds. %d ips." % (unindexed_fns[0], time.time() - st, len(ips)))
            sys.stdout.flush()
        else:
            ips = set()
            for fn in unindexed_fns:
                st = time.time()
                new_ips = self.get_bytes(fn)
                if len(new_ips) > 0:
                    ips.update(new_ips)
                print("read %s in %0.1f seconds. %d ips." % (fn, time.time() - st, len(ips)))
                sys.stdout.flush()

        doc = xapian.Document()

        if len(ips) > 0:
            list(map(doc.add_term, ips))

        for fn in unindexed_fns:
            doc.add_term("fn:%s" % fn)

        #docid is the hour part of the filename
        docid = self.fn_to_docid(fn)
        doc.set_data(docid)
        key = "fn:%s" % docid
        doc.add_term(key)
        database.replace_document(key, doc)
        self.dirty = True
        self.maybe_flush()

        #print 'loading data into xapian took %0.1f seconds. %0.1f total' % (time.time() - st, time.time() - begin)
