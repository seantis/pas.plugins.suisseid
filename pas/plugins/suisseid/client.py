import time
import dateutil.parser
import base64
import sys

from saml2 import samlp
from saml2.sigver import XMLSEC_BINARY, _TEST_
from saml2.sigver import SignatureError, make_temp, cert_from_instance, verify_signature, correctly_signed_response
from saml2.client import Saml2Client as BaseClient
from saml2.client import for_me

RESPONSE_NODE = 'urn:oasis:names:tc:SAML:2.0:protocol:Response'

class Saml2Client(BaseClient):
    
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
        response = correctly_signed_response(decoded_xml, 
                        self.config["xmlsec_binary"], log=log,
                        metadata=self.config['metadata'])
        if not response:
            if log:
                log.error("Response was not correctly signed")
                log.info(decoded_xml)
            return None
        else:
            log and log.error("Response was correctly signed or nor signed")
        
        log and log.info("response: %s" % (response,))
        try:
            session_info = self.do_response(response, 
                                                requestor, 
                                                outstanding=outstanding, 
                                                xmlstr=xmlstr, 
                                                log=log, context=context,
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