import base64
import unittest
import os
import urllib
from StringIO import StringIO
from datetime import datetime, timedelta

path = os.path.dirname(__file__)
xmlsec_binary = '/usr/local/bin/xmlsec1'

class TestSuisseIdExtraction(unittest.TestCase):

    def createPlugin(self):
        from pas.plugins.suisseid.tests.utils import MockPAS
        from pas.plugins.suisseid.plugin import SuisseIDPlugin
        plugin = SuisseIDPlugin("suisseid")
        plugin.changeConfiguration('suisseID Test Portal', 'http://nohost/', '',
                                   '', '', '', '', xmlsec_binary, '')
        pas = MockPAS()
        return plugin.__of__(pas)
        
    def createIdpResponse(self, authn_request_id='2aaaeb7692471eb4ba00d5546877a7fd'):
        from saml2.saml import Issuer, Assertion
        from saml2.saml import Subject, NameID, SubjectConfirmation, SubjectConfirmationData
        from saml2.saml import Conditions, AudienceRestriction, Audience, OneTimeUse
        from saml2.saml import AuthnStatement, AuthnContext, AuthnContextClassRef
        from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, SUBJECT_CONFIRMATION_METHOD_BEARER
        from saml2.saml import NAMEID_FORMAT_ENTITY
        from saml2.samlp import Response, Status, StatusCode
        from saml2.samlp import STATUS_SUCCESS
        from saml2.utils import make_instance
        from saml2.sigver import pre_signature_part
        from xmldsig import Signature
        
        issue_instant = datetime.utcnow().isoformat() + 'Z'
        not_before = (datetime.utcnow() - timedelta(minutes=5)).isoformat() + 'Z'
        not_on_or_after = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + 'Z'
        issuer = Issuer(format=NAMEID_FORMAT_ENTITY, text='https://idp.swisssign.net/suisseid/eidp')
        signature = make_instance(Signature, pre_signature_part('_ea7f4526-43a3-42d6-a0bc-8f367e95802f'))
        status = Status(status_code=StatusCode(value=STATUS_SUCCESS))
        subject_confirmation_data = SubjectConfirmationData(not_on_or_after=not_on_or_after,
                                                            in_response_to=authn_request_id,
                                                            recipient='http://nohost/')
        subject_confirmation = SubjectConfirmation(method=SUBJECT_CONFIRMATION_METHOD_BEARER,
                                                   subject_confirmation_data=subject_confirmation_data)
        subject = Subject(name_id=NameID(text='1234-1234-1234-1234', format=NAMEID_FORMAT_UNSPECIFIED), 
                          subject_confirmation=subject_confirmation)
        conditions = Conditions(not_before=not_before,
                                not_on_or_after=not_on_or_after,
                                audience_restriction=AudienceRestriction(Audience('http://nohost/')),
                                one_time_use=OneTimeUse())
        authn_context = AuthnContext(authn_context_decl_ref=AuthnContextClassRef('urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI'))
        authn_statement = AuthnStatement(authn_instant=issue_instant,
                                         authn_context=authn_context)
        assertion_signature = make_instance(Signature, pre_signature_part('_cb8e7dc8-00b3-4655-ad2d-d083cae5168d'))
        assertion = Assertion(id='_cb8e7dc8-00b3-4655-ad2d-d083cae5168d',
                              version='2.0',
                              issue_instant=issue_instant,
                              issuer=issuer,
                              signature=assertion_signature,
                              subject=subject,
                              conditions=conditions,
                              authn_statement=authn_statement,
                             )
        
        response = Response(id='_ea7f4526-43a3-42d6-a0bc-8f367e95802f',
                            in_response_to=authn_request_id,
                            version='2.0',
                            issue_instant=issue_instant,
                            destination='http://nohost/',
                            issuer=issuer,
                            signature=signature,
                            status=status,
                            assertion=assertion,
                           )
        
        return response
        
    def sign_response(self, response):
        from saml2.sigver import sign_statement_using_xmlsec
        response = '%s' % response
        # Sign assertion in the response
        signed_response = sign_statement_using_xmlsec(response, "Response",
                                xmlsec_binary,
                                key_file=os.path.join(path, 'data', 'idp.key'))
        return signed_response
        
    def testNoProviderExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest
        plugin = self.createPlugin()
        request = MockRequest()
        result = plugin.extractCredentials(request)
        self.assertEquals(result, {})
        
    def testEmptyProviderExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest
        plugin = self.createPlugin()
        request = MockRequest()
        request.form['__ac_suisseid_provider_url'] = ''
        result = plugin.extractCredentials(request)
        self.assertEquals(result, {})
        
    def testAuthnRequestExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest, FormParser
        from saml2.samlp import authn_request_from_string
        plugin = self.createPlugin()
        plugin.changeConfiguration('', 'http://nohost/', '', '', '', '', '', xmlsec_binary,
                                   os.path.join(path, 'data', 'metadata.xml'))
        request = MockRequest()
        request.form['__ac_suisseid_provider_url'] = 'https://idp.swisssign.net/suisseid/eidp/'
        result = plugin.extractCredentials(request)
        # No credentials since that's only the first step
        self.assertEquals(result, None)
        response = request.response
        self.assertEquals(response.status, 200)
        self.assertEquals(response.headers['Content-type'], 'text/html')
        parser = FormParser()
        parser.parse(response.body)
        saml_request = parser.inputs['SAMLRequest']
        decoded_xml = base64.b64decode(saml_request)
        request = authn_request_from_string(decoded_xml)
        self.assertEquals(request.destination, 'https://idp.swisssign.net/suisseid/eidp/')
        self.assertEquals(request.assertion_consumer_service_url, plugin.getConfiguration()['portal_url'])
        
    def testAuthnRequestSignedExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest, FormParser
        from saml2.samlp import authn_request_from_string
        plugin = self.createPlugin()
        sp_pem = os.path.join(path, 'data', 'sp.pem')
        sp_key = os.path.join(path, 'data', 'sp.key')
        plugin.changeConfiguration('suisseID Test Portal', 'http://nohost/', '',
                                   '', '', sp_key, sp_pem, xmlsec_binary, '')
        request = MockRequest()
        request.form['__ac_suisseid_provider_url'] = 'https://idp.swisssign.net/suisseid/eidp/'
        plugin.extractCredentials(request)
        parser = FormParser()
        parser.parse(request.response.body)
        saml_request = parser.inputs['SAMLRequest']
        decoded_xml = base64.b64decode(saml_request)
        request = authn_request_from_string(decoded_xml)
        self.assertEquals(request.destination, 'https://idp.swisssign.net/suisseid/eidp/')
        # Verify signature
        from saml2.sigver import verify_signature
        verified = verify_signature(xmlsec_binary, decoded_xml, sp_pem, 
                                    node_name='urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest', 
                                    cert_type='pem')
        self.assertEquals(verified, True)
        
    def testExtendedAuthnRequestExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest, FormParser
        from saml2.samlp import authn_request_from_string
        plugin = self.createPlugin()
        request = MockRequest()
        request.form['__ac_suisseid_provider_url'] = 'https://idp.swisssign.net/suisseid/eidp/'
        # Request three attributes: First Name (required), Last Name (required) and isOver18 (optional)
        plugin.changeConfiguration('suisseID Test Portal', 'http://nohost/', 'First Name\r\nLast Name',
                                   'isOver18', '', '', '', xmlsec_binary, '')
                                   
        request = MockRequest()
        request.form['__ac_suisseid_provider_url'] = 'https://idp.swisssign.net/suisseid/eidp/'
        plugin.extractCredentials(request)
        parser = FormParser()
        parser.parse(request.response.body)
        saml_request = parser.inputs['SAMLRequest']
        decoded_xml = base64.b64decode(saml_request)
        request = authn_request_from_string(decoded_xml)
        self.assertEquals(request.force_authn, 'true')
        extenions = request.extensions.extension_elements
        self.assertEquals(len(extenions), 3)
        self.assertEquals(extenions[0].attributes['Name'], 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname')
        self.assertEquals(extenions[0].attributes['{http://www.ech.ch/xmlns/eCH-0113/1}required'], 'true')
        
    # Second step of Authentication (SAML response from Idp)
    
    def testResponseExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest
        plugin = self.createPlugin()
        plugin.changeConfiguration('', 'http://nohost/', '', '', '', '', '', '/usr/local/bin/xmlsec1',
                                   os.path.join(path, 'data', 'metadata.xml'))
        request = MockRequest()
        # There has to be an outstanding AuthnRequest
        request.SESSION['suisseid'] = { '2aaaeb7692471eb4ba00d5546877a7fd' : '' }
        # Create a SAML2 response
        response = '%s' % self.createIdpResponse('2aaaeb7692471eb4ba00d5546877a7fd')
        signed_response = self.sign_response(response)
        encoded_response = base64.b64encode(signed_response)
        request.form['SAMLResponse'] = encoded_response
        request.environ['REQUEST_METHOD'] = 'POST'
        request.stdin = StringIO(urllib.urlencode({'SAMLResponse' : encoded_response}))
        creds = plugin.extractCredentials(request)
        self.assertEquals(creds['login'], '1234-1234-1234-1234')
        
    def testResponseAuthnFailedExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest
        plugin = self.createPlugin()
        plugin.changeConfiguration('', 'http://nohost/', '', '', '', '', '', xmlsec_binary,
                                   os.path.join(path, 'data', 'metadata.xml'))
        request = MockRequest()
        # There has to be an outstanding AuthnRequest
        request.SESSION['suisseid'] = { '2aaaeb7692471eb4ba00d5546877a7fd' : '' }
        # Create a SAML2 response
        response = self.createIdpResponse('2aaaeb7692471eb4ba00d5546877a7fd')
        from saml2.samlp import StatusCode, STATUS_AUTHN_FAILED
        response.status.status_code = StatusCode(value=STATUS_AUTHN_FAILED)
        response = '%s' % response
        signed_response = self.sign_response(response)
        encoded_response = base64.b64encode(signed_response)
        request.form['SAMLResponse'] = encoded_response
        request.environ['REQUEST_METHOD'] = 'POST'
        request.stdin = StringIO(urllib.urlencode({'SAMLResponse' : encoded_response}))
        creds = plugin.extractCredentials(request)
        self.assertEquals(creds, None)
        
    def testResponseManipulatedExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest
        plugin = self.createPlugin()
        plugin.changeConfiguration('', 'http://nohost/', '', '', '', '', '', xmlsec_binary,
                                   os.path.join(path, 'data', 'metadata.xml'))
        request = MockRequest()
        # There has to be an outstanding AuthnRequest
        request.SESSION['suisseid'] = { '2aaaeb7692471eb4ba00d5546877a7fd' : '' }
        # Create a SAML2 response
        response = '%s' % self.createIdpResponse('2aaaeb7692471eb4ba00d5546877a7fd')
        signed_response = self.sign_response(response)
        # Response has been manipulated by third party (suisseID number changed).
        signed_response = signed_response.replace('1234-1234-1234-1234', '1234-1234-1234-1235')
        encoded_response = base64.b64encode(signed_response)
        request.form['SAMLResponse'] = encoded_response
        request.environ['REQUEST_METHOD'] = 'POST'
        request.stdin = StringIO(urllib.urlencode({'SAMLResponse' : encoded_response}))
        from saml2.sigver import SignatureError
        self.assertRaises(SignatureError, plugin.extractCredentials, request)
        
    def testResponseNoOutstandingAuthnRequestExtraction(self):
        from pas.plugins.suisseid.tests.utils import MockRequest
        plugin = self.createPlugin()
        plugin.changeConfiguration('', 'http://nohost/', '', '', '', '', '', xmlsec_binary,
                                   os.path.join(path, 'data', 'metadata.xml'))
        request = MockRequest()
        # There are no outstanding AuthnRequesta
        request.SESSION['suisseid'] = {}
        # Create a SAML2 response
        response = '%s' % self.createIdpResponse()
        signed_response = self.sign_response(response)
        encoded_response = base64.b64encode(signed_response)
        request.form['SAMLResponse'] = encoded_response
        request.environ['REQUEST_METHOD'] = 'POST'
        request.stdin = StringIO(urllib.urlencode({'SAMLResponse' : encoded_response}))
        creds = plugin.extractCredentials(request)
        self.assertEquals(creds, None)
