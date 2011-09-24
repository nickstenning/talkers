import logging
import multiprocessing
import os
import random
import select
import signal
import sys

import pybonjour

log = logging.getLogger(__name__)

REGTYPE = "_talker._tcp"

class NameResolutionError(Exception):
    pass

class Talker(multiprocessing.Process):
    def __init__(self, type):
        self.type = type
        self.id = random.randint(0, 0xffffffff)
        self.time_to_die = False
        self.port = random.randint(40000, 60000)
        self.resolve_timeout = 5
        self.resolved = []
        self.services = {}
        self.pipe_client, self.pipe = multiprocessing.Pipe()
        super(Talker, self).__init__()

    def register(self):
        self.sd_ref = pybonjour.DNSServiceRegister(name=str(hex(self.id)),
                                                   regtype=REGTYPE,
                                                   port=self.port,
                                                   txtRecord=self._txt_record(),
                                                   callBack=self._register_callback)

    def unregister(self):
        self.sd_ref.close()

    def browse(self):
        self.browse_sd_ref = pybonjour.DNSServiceBrowse(regtype=REGTYPE,
                                                        callBack=self._browse_callback)

    def unbrowse(self):
        self.browse_sd_ref.close()

    def run(self):
        self.register()
        self.browse()

        try:
            while not self.time_to_die:
                ready = select.select([self.sd_ref,
                                       self.browse_sd_ref,
                                       self.pipe],
                                      [], [])

                if self.sd_ref in ready[0]:
                    pybonjour.DNSServiceProcessResult(self.sd_ref)

                if self.browse_sd_ref in ready[0]:
                    pybonjour.DNSServiceProcessResult(self.browse_sd_ref)

                if self.pipe in ready[0]:
                    self._process_message(self.pipe.recv())
        finally:
            self.unregister()
            self.unbrowse()

    def _txt_record(self):
        pfx = "type="
        length = len(self.type) + len(pfx)

        if length > 0xff:
            raise Exception("Type string too long (max %d bytes): '%s'" %
                            (0xff - len(pfx), self.type))

        rec = "%s%s%s" % (chr(length), pfx, self.type)
        return rec

    def _register_callback(self, sd_ref, flags, error_code, name, regtype, domain):
        if error_code != pybonjour.kDNSServiceErr_NoError:
            raise pybonjour.BonjourError(error_code)

    def _browse_callback(self, sd_ref, flags, interface_index,
                         error_code, name, regtype, domain):

        if error_code != pybonjour.kDNSServiceErr_NoError:
            raise pybonjour.BonjourError(error_code)

        if not (flags & pybonjour.kDNSServiceFlagsAdd):
            log.debug("Saw service removal: %s", name)
            self._remove_service(name)
            return

        log.debug("Saw service addition: %s. Resolving...", name)

        resolve_sd_ref = pybonjour.DNSServiceResolve(0,
                                                     interface_index,
                                                     name,
                                                     regtype,
                                                     domain,
                                                     self._resolve_callback)

        try:
            while not self.resolved:
                ready = select.select([resolve_sd_ref], [], [],
                                      self.resolve_timeout)

                if resolve_sd_ref not in ready[0]:
                    raise NameResolutionError('Resolve timed out')

                pybonjour.DNSServiceProcessResult(resolve_sd_ref)
            else:
                self.resolved.pop()
        finally:
            resolve_sd_ref.close()


    def _resolve_callback(self, sd_ref, flags, interface_index,
                          error_code, name, target, port, txt_record):
        if error_code != pybonjour.kDNSServiceErr_NoError:
            raise pybonjour.BonjourError(error_code)

        self._add_service(name, target, port, txt_record)

        self.resolved.append(True)

    def _add_service(self, name, target, port, txt_record):
        id_ = int(name.split('.')[0], 16)

        if id_ in self.services.keys():
            return

        self.services[id_] = {
            'hostname': target,
            'port': port,
            'txt_record': txt_record[1:]
        }

        self.pipe.send(self.services)
        log.info("Added service: {name}, at {target}:{port}".format(**locals()))

    def _remove_service(self, name):
        id_ = int(name.split('.')[0], 16)

        if id_ not in self.services.keys():
            return

        del self.services[id_]
        log.info("Removed service: {name}".format(**locals()))

    def _process_message(self, msg):
        if msg == 'quit':
            log.info("Got quit msg. Scheduling termination...")
            self.time_to_die = True

    def __enter__(self):
        self.start()
        return self.pipe_client

    def __exit__(self, type, value, traceback):
        self.pipe_client.send('quit')
        self.join()
