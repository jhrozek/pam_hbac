#!/usr/bin/env python

import unittest
import os
import shutil
import ssl
import urllib
import urllib2
import json

from cookielib import CookieJar

import pypamtest

class IpaClientlessTestDriver(object):
    def __init__(self,
                 hostname, password,
                 username='admin', insecure=False):
        self.hostname = hostname
        self.password = password
        self.username = username
        self.referer = "https://" + self.hostname + "/ipa"

        self.cj = CookieJar()
        self.ssl_ctx = self._ssl_ctx(insecure)

    def _auth(self, lazy=True):
        if lazy == True and len(self.cj) > 0:
            return 200

        login_url = self.referer + "/session/login_password"

        request = urllib2.Request(login_url)
        request.add_header('referer', self.referer)
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        request.add_header('Accept', 'text/plain')

        query_args = { 'user' : self.username,
                       'password' : self.password
                     }
        encoded_args = urllib.urlencode(query_args)

        result = urllib2.urlopen(request,
                                 encoded_args,
                                 context=self.ssl_ctx)
        if result.getcode() == 200:
            self.cj.extract_cookies(result, request)
        return result.getcode()

    def _ssl_ctx(self, insecure):
        ctx = ssl.create_default_context()
        if insecure == True:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _json_request(self, jdata):
        ret = self._auth()
        if ret != 200:
            return ret

        json_url = self.referer + "/session/json"
        request = urllib2.Request(json_url)

        request.add_header('referer', self.referer)
        request.add_header('Content-Type', 'application/json')
        request.add_header('Accept', 'application/json')

        self.cj.add_cookie_header(request)
        result = urllib2.urlopen(request,
                                 jdata,
                                 context=self.ssl_ctx)
        return result.getcode()

    def run_cmd(self, method, params):
        cmd = json.dumps({"method":method, "params":[params,{}], "id":"0"})
        return self._json_request(cmd)

class IpaClientlessPamHbacRule(object):
    def __init__(self, driver, name):
        self.driver = driver
        self.name = name

    def create(self, usercat=None, hostcat=None, servicecat=None):
        pass

    def add_svc(self, svcs=None, svcgroups=None):
        pass

    def add_user(self, users=None, usergroups=None):
        pass

    def add_host(self, hosts=None, hostgroups=None):
        pass

    def enable(self):
        self.driver.run_cmd("hbacrule_enable", [ self.name ])

    def disable(self):
        self.driver.run_cmd("hbacrule_disable", [ self.name ])

class PamHbacTestCase(unittest.TestCase):
    def setUp(self):
        self._pwrap_setup()
        self._driver_setup()


    def assertPamReturns(self, user, service, rc):
        self._config_setup()
        svc_file = self._write_pam_svc_file(service,
                                            self.ph_abspath,
                                            self.config_file.name)
        try:
            tc = pypamtest.TestCase(pypamtest.PAMTEST_ACCOUNT, rc)
            self._run_pwrap_test(tc, user, service)
        finally:
            os.unlink(svc_file.name)


    def assertAllowed(self, user, service):
        self.assertPamReturns(user, service, 0)


    def assertDenied(self, user, service):
        self.assertPamReturns(user, service, 6)


    def _run_pwrap_test(self, tc, user, service):
        res = pypamtest.run_pamtest(user, service, [tc])


    def _driver_setup(self):
        ipa_hostname = os.getenv("IPA_HOSTNAME")
        if ipa_hostname == None:
            raise ValueError("IPA server hostname to test against is not set!\n")

        admin_password = os.getenv("ADMIN_PASSWORD")
        if admin_password == None:
            raise ValueError("IPA admin password is not set!\n")

        insecure = os.getenv("INSECURE_TESTS")
        if insecure != None:
            insecure = True

        self.driver = IpaClientlessTestDriver(ipa_hostname,
                                              admin_password,
                                              insecure=True)


    def _pwrap_setup(self):
        if os.getenv("PAM_WRAPPER") == None:
            raise ValueError("PAM_WRAPPER is not initialized\n")

        self.pwrap_runtimedir = os.getenv("PAM_WRAPPER_RUNTIME_DIR")
        if self.pwrap_runtimedir == None:
            raise ValueError("The PAM_WRAPPER_RUNTIME_DIR variable is unset\n")

        if not os.access(self.pwrap_runtimedir, os.O_RDWR):
            raise IOError("Cannot access %s\n", self.pwrap_runtimedir)

        self.ph_abspath = os.getenv("PAM_HBAC_ABS_PATH")
        if self.ph_abspath == None:
            raise ValueError("The pam_hbac absolute path is unset\n")


    def _config_write(self, config_path, confd):
        f = open(config_path, 'w')
        for key in confd:
            f.write("%s=%s\n" % (key, confd[key]))
        f.flush()
        return f


    def _config_setup(self):
        self.config_file = None

        config_path = os.getenv("PAM_HBAC_CONFIG_PATH")
        if config_path == None:
            return

        base_dn = os.getenv("IPA_BASEDN")
        if base_dn == None:
            raise ValueError("IPA server basedn to test against is not set!\n")

        confd = {}
        confd['URI'] = "ldap://" + self.driver.hostname
        confd['BASE'] = base_dn
        confd['BIND_DN'] = "uid=admin,cn=users,cn=accounts," + base_dn
        confd['BIND_PW'] = self.driver.password

        client_hostname = os.getenv("HOST_NAME")
        if client_hostname:
            confd['HOST_NAME'] = client_hostname

        self.config_file = self._config_write(config_path, confd)


    def _write_pam_svc_file(self, svc_name, module_abspath, config_file=None):
        svcfile = os.path.join(self.pwrap_runtimedir, svc_name)
        f = open(svcfile, 'w')
        content = self._gen_pam_svc_file(module_abspath, config_file)
        f.write(content)
        f.flush()
        return f


    def _gen_pam_svc_file(self, module_abspath, config_file=None):
        content = "account required %s" % module_abspath
        if config_file != None:
            content = content + " config=%s" % config_file
        content = content + "\n"
        return content


class PamHbacTestAllowAll(PamHbacTestCase):
    def setUp(self):
        super(PamHbacTestAllowAll, self).setUp()


    def tearDown(self):
        super(PamHbacTestAllowAll, self).tearDown()


    def test_allow_all(self):
        rule = IpaClientlessPamHbacRule(self.driver, "allow_all")
        rule.enable()
        self.assertAllowed("admin", "sshd")

    def test_allow_all_disabled(self):
        rule = IpaClientlessPamHbacRule(self.driver, "allow_all")
        rule.disable()
        self.assertDenied("admin", "sshd")
        rule.enable()

class PamHbacTestErrorConditions(PamHbacTestCase):
    def setUp(self):
        super(PamHbacTestErrorConditions, self).setUp()


    def tearDown(self):
        super(PamHbacTestErrorConditions, self).tearDown()


    def test_no_such_user(self):
        """"
        Unknown user should return 10 = User not known to the underlying module,
        at least on Linux
        """
        self.assertPamReturns("no_such_user", "sshd", 10)


    def test_no_such_service(self):
        """"
        Unknown user should return 10 = User not known to the underlying module,
        at least on Linux
        """
        self.assertPamReturns("admin", "no_such_service", 6)


    def test_no_such_host(self):
        """"
        Unknown host should just deny access
        """
        old_hostname = os.environ["HOST_NAME"]
        os.environ["HOST_NAME"] = "no_such_host"
        try:
            self.assertPamReturns("admin", "sshd", 6)
        finally:
            os.environ["HOST_NAME"] = old_hostname


if __name__ == "__main__":
    unittest.main()
