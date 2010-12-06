import time
import dateutil.parser
import base64
import sys
import os

import xmldsig as ds
import saml2
from saml2 import samlp, saml
from saml2 import VERSION, class_name
from saml2.time_util import instant
from saml2.utils import sid, make_instance
from saml2.sigver import XMLSEC_BINARY, _TEST_
from saml2.sigver import SignatureError, make_temp, cert_from_instance, verify_signature
from saml2.sigver import pre_signature_part, sign_statement_using_xmlsec
from saml2.client import Saml2Client as BaseClient
from saml2.client import for_me

from ech0113 import ExtendedAttribute, PrivacyNotice

FORM_SPEC = """<form method="post" action="%s">
   <input type="hidden" name="SAMLRequest" value="%s" />
   <input type="hidden" name="RelayState" value="%s" />
   <noscript><p>Click 'Continue' to send the request manually.</p><input type="submit" value="Continue" /></noscript>
</form>"""

RESPONSE_NODE = 'urn:oasis:names:tc:SAML:2.0:protocol:Response'

class Saml2Client(BaseClient):
    
    def extended_authn_request(self, query_id, destination, service_url, spentityid, 
                        my_name, vorg="", scoping=None, log=None, sign=False,
                        required_attributes=[], optional_attributes=[], privacy_notice=None):
        """ Creates an authentication request.
        
        :param query_id: The identifier for this request
        :param destination: Where the request should be sent.
        :param service_url: Where the reply should be sent.
        :param spentityid: The entity identifier for this service.
        :param my_name: The name of this service.
        :param vorg: The vitual organization the service belongs to.
        :param scoping: The scope of the request
        :param log: A service to which logs should be written
        :param sign: Whether the request should be signed or not.
        :param required_attributes: Required attributes
        :param optional_attributes: Optional attributes
        """
        prel = {
            "id": query_id,
            "version": VERSION,
            "issue_instant": instant(),
            "destination": destination,
            "assertion_consumer_service_url": service_url,
            "protocol_binding": saml2.BINDING_HTTP_POST,
            "provider_name": my_name,
        }
        
        if scoping:
            prel["scoping"] = scoping
            
        name_id_policy = {
            "allow_create": "true"
        }
        
        # see suisseID Spec. 3.6.1.3 Username in the SAML Assertion - NameID Format
        name_id_policy["format"] = saml.NAMEID_FORMAT_UNSPECIFIED
        
        if vorg:
            try:
                name_id_policy["sp_name_qualifier"] = vorg
                name_id_policy["format"] = saml.NAMEID_FORMAT_PERSISTENT
            except KeyError:
                pass
        
        if sign:
            prel["signature"] = pre_signature_part(prel["id"])

        prel["name_id_policy"] = name_id_policy
        prel["issuer"] = { "text": spentityid }
        
        if log:
            log.info("DICT VERSION: %s" % prel)
            
        request = make_instance(samlp.AuthnRequest, prel)
        
        extensions = []
        for attribute in required_attributes:
            name_format = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
            extensions.append(ExtendedAttribute(name_format=name_format, name=attribute, required='true'))
        for attribute in optional_attributes:
            name_format = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
            extensions.append(saml.Attribute(name_format=name_format, name=attribute))
        
        if privacy_notice:
            extensions.append(PrivacyNotice(text=privacy_notice))
            
        if extensions:
            request.extensions = samlp.Extensions(extension_elements=extensions)
            request.force_authn = 'true'
        
        if sign:
            
            # Add public key to Signature
            fd = open(self.config["cert_file"], 'r')
            pub_key = fd.read()
            fd.close()
            pub_key = pub_key.replace('-----BEGIN CERTIFICATE-----', '')
            pub_key = pub_key.replace('-----END CERTIFICATE-----', '')
            pub_key = pub_key.replace('\n', '')
            x509_certificate = ds.X509Certificate(pub_key)
            x509_data = ds.X509Data(x509_certificate=x509_certificate)
            request.signature.key_info = ds.KeyInfo(x509_data=x509_data)
            
            return sign_statement_using_xmlsec("%s" % request, class_name(request),
                                    self.config["xmlsec_binary"], 
                                    key_file=self.config["key_file"])
                                    
            #return samlp.authn_request_from_string(sreq)
        else:
            return "%s" % request
            
    def authenticate(self, spentityid, location="", service_url="", 
                        my_name="", relay_state="",
                        binding=saml2.BINDING_HTTP_POST, log=None,
                        vorg="", scoping=None,
                        required_attributes=[], optional_attributes=[],
                        privacy_notice=None):
        """ Either verifies an authentication Response or if none is present
        send an authentication request.
        
        :param spentityid: The SP EntityID
        :param binding: How the authentication request should be sent to the 
            IdP
        :param location: Where the IdP is.
        :param service_url: The SP's service URL
        :param my_name: The providers name
        :param relay_state: To where the user should be returned after 
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param vorg: The entity_id of the virtual organization I'm a member of
        :param scoping: For which IdPs this query are aimed.
            
        :return: AuthnRequest response
        """
        
        if log:
            log.info("spentityid: %s" % spentityid)
            log.info("location: %s" % location)
            log.info("service_url: %s" % service_url)
            log.info("my_name: %s" % my_name)
        session_id = sid()
        
        sign = self.config["key_file"] and self.config["cert_file"]
        
        authen_req = self.extended_authn_request(session_id, location, 
                                service_url, spentityid, my_name, vorg, 
                                scoping, log, sign,
                                required_attributes=required_attributes, 
                                optional_attributes=optional_attributes,
                                privacy_notice=privacy_notice)
        log and log.info("AuthNReq: %s" % authen_req)
        
        if binding == saml2.BINDING_HTTP_POST:
            response = []
            response.append("<html>")
            response.append("<head>")
            response.append("""<title>SAML 2.0 POST</title>""")
            response.append("</head><body>")
            response.append(FORM_SPEC % (location, base64.b64encode(authen_req), relay_state))
            response.append("""<script type="text/javascript">""")
            response.append("     window.onload = function ()")
            response.append(" { document.forms[0].submit(); }")
            response.append("""</script>""")
            response.append("</body>")
            response.append("</html>")
        elif binding == saml2.BINDING_HTTP_REDIRECT:
            raise Exception("HTTP redirect binding type not supported by suisseID" )
        else:
            raise Exception("Unkown binding type: %s" % binding)
        return (session_id, response)
    
    def _verify_condition(self, assertion, requestor, log, lax=False, 
                        slack=0):
        # The Identity Provider MUST include a <saml:Conditions> element
        #print "Conditions",assertion.conditions
        assert assertion.conditions
        condition = assertion.conditions
        log and log.info("condition: %s" % condition)

        try:
            slack = self.config["accept_time_diff"]
        except KeyError:
            slack = 0

        try:
            not_on_or_after = _use_on_or_after(condition, slack)
            _use_before(condition, slack)
        except Exception:
            if not lax:
                raise
            else:
                not_on_or_after = 0
            
        if not for_me(condition, requestor):
            raise Exception("Not for me!!!")
    
        return not_on_or_after

    def verify_response(self, xml_response, requestor, outstanding=None, 
                log=None, decode=True, context="", lax=False):
        """ Verify a response
    
        :param xml_response: The response as a XML string
        :param requestor: The hostname of the machine
        :param outstanding: A collection of outstanding authentication requests
        :param log: Where logging information should be sent
        :param decode: There for testing purposes
        :param lax: Accept things you normally shouldn't
        :return: A 2-tuple consisting of an identity description and the 
            real relay-state
        """
    
        if not outstanding:
            outstanding = {}
    
        if decode:
            decoded_xml = base64.b64decode(xml_response)
        else:
            decoded_xml = xml_response
    
        # own copy
        xmlstr = decoded_xml[:]
        log and log.info("verify correct signature")
        # IdP/CAS must sign assertion, thus must=True
        response = correctly_signed_response(decoded_xml, 
                        self.config["xmlsec_binary"], log=log,
                        metadata=self.config['metadata'])
        if not response:
            if log:
                log.error("Response was not correctly signed")
                log.info(decoded_xml)
            return None
        else:
            log and log.info("Response was correctly signed")
        
        log and log.info("response: %s" % (response,))
        try:
            session_info = self.do_response(response, 
                                            requestor, 
                                            outstanding=outstanding, 
                                            xmlstr=xmlstr, 
                                            log=log, 
                                            context=context,
                                            lax=lax)
            session_info["issuer"] = response.issuer.text
            session_info["session_id"] = response.in_response_to
        except AttributeError, exc:
            if log:
                log.error("AttributeError: %s" % (exc,))
            else:
                print >> sys.stderr, "AttributeError: %s" % (exc,)
            return None
        except Exception, exc:
            if log:
                log.error("Exception: %s" % (exc,))
            else:
                print >> sys.stderr, "Exception: %s" % (exc,)
            return None
                                
        session_info["ava"]["__userid"] = session_info["name_id"]
        return session_info
        
        
def correctly_signed_response(decoded_xml,
        xmlsec_binary=XMLSEC_BINARY, metadata=None, log=None, must=False):
    """ Check if a instance is correctly signed, if we have metadata for
    the IdP that sent the info use that, if not use the key that are in 
    the message if any.

    :param decode_xml: The SAML message as a XML string
    :param xmlsec_binary: Where the xmlsec1 binary can be found on this
        system.
    :param metadata: Metadata information
    :return: None if the signature can not be verified otherwise an instance
    """

    print "-- correctly_signed_response --"
    response = samlp.response_from_string(decoded_xml)

    if not xmlsec_binary:
        xmlsec_binary = XMLSEC_BINARY

    # Try to find the signing cert in the assertion
    for assertion in response.assertion:
        if not assertion.signature:
            if _TEST_:
                log and log.info("unsigned")
            if must:
                raise SignatureError("Signature missing")
            continue
        else:
            if _TEST_:
                log and log.info("signed")
    
        issuer = assertion.issuer.text.strip()
        if _TEST_:
            print "issuer: %s" % issuer
        if metadata:
            certs = metadata.certs(issuer)
        else:
            certs = []

        if _TEST_:
            print "metadata certs: %s" % certs

        if not certs:
            certs = [make_temp("%s" % cert, ".der") \
                        for cert in cert_from_instance(assertion)]
        if not certs:
            raise SignatureError("Missing certificate")

        verified = False
        for _, der_file in certs:
            if verify_signature(xmlsec_binary, decoded_xml, der_file, node_name=RESPONSE_NODE):
                verified = True
                break
                
        if not verified:
            raise SignatureError("Could not verify")

    return response
   

def _use_on_or_after(condition, slack):
    now = time.mktime(time.gmtime())
    not_on_or_after = dateutil.parser.parse(condition.not_on_or_after)
    not_on_or_after = time.mktime(not_on_or_after.utctimetuple())
    if not_on_or_after < now + slack:
        # To old ignore
        raise Exception("To old can't use it (%s < %s)" % ( not_on_or_after,
                        (now + slack)))
    return not_on_or_after
    
def _use_before(condition, slack):
    not_before = dateutil.parser.parse(condition.not_before)
    not_before = time.mktime(not_before.utctimetuple())
    now = time.mktime(time.gmtime())
        
    if not_before > now + slack:
        # Can't use it yet
        raise Exception("Can't use it yet %s > %s" % (not_before, now)) 