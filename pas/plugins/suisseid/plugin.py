import os
import cgi
from cStringIO import StringIO
import logging
import re

from App.Common import package_home
from AccessControl.SecurityInfo import ClassSecurityInfo
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins \
                import IAuthenticationPlugin, IUserEnumerationPlugin, IExtractionPlugin
from Products.PluggableAuthService.permissions import ManageUsers

from Products.CMFCore.utils import getToolByName

from client import Saml2Client
from saml2.config import Config
from config import sp_config

_browserdir = os.path.join( package_home( globals() ), 'www' )

manage_addSuisseIDPlugin = PageTemplateFile("../www/suisseIDAdd", globals(), 
                __name__="manage_addSuisseIDPlugin")

logger = logging.getLogger("PluggableAuthService")

suisseid_format = re.compile('[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}')

attributes = {
    'First Name' : 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'Last Name' : 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
}

def addSuisseIDPlugin(self, id, title='', REQUEST=None):
    """Add a suisseID plugin to a Pluggable Authentication Service.
    """
    p=SuisseIDPlugin(id, title)
    self._setObject(p.getId(), p)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect("%s/manage_workspace"
                "?manage_tabs_message=suisseID+plugin+added." %
                self.absolute_url())

class SuisseIDPlugin(BasePlugin):
    """suisseID authentication plugin.
    """

    meta_type = "suisseID plugin"
    security = ClassSecurityInfo()

    def __init__(self, id, title=None):
        self._setId(id)
        self.title=title
        self.config = {}
        self._setConfiguration()
        
    def _saml2_config(self):
        if hasattr(self, '_v_cached_config') and self._v_cached_config:
            return self._v_cached_config
        config = Config()
        config.load(sp_config.copy())
        config['entityid'] = self.config['portal_url']
        config['service']['sp']['name'] = self.config['portal_name']
        config['service']['sp']['url'] = self.config['portal_url']
        required_attributes = []
        for attribute in self.config['required_attributes'].split('\r\n'):
            name = attributes.get(attribute, None)
            if name:
                required_attributes.append(name)
        optional_attributes = []
        for attribute in self.config['optional_attributes'].split('\r\n'):
            name = attributes.get(attribute, None)
            if name:
                optional_attributes.append(name)
        config['service']['sp']['required_attributes'] = required_attributes
        config['service']['sp']['optional_attributes'] = optional_attributes
        config['key_file'] = self.config['key_file']
        config['cert_file'] = self.config['cert_file']
        config['xmlsec_binary'] = self.config['xmlsec_binary']
        
        # Get Idps from the metadata
        config['service']['sp']['idp'] = {}
        for location in config['metadata'].locations():
            name = config['metadata'].name(location)
            config['service']['sp']['idp'][name] = location
        
        self._v_cached_config = config
        return self._v_cached_config
        
    def getProviders(self):
        config = self._saml2_config()
        providers = config['service']['sp']['idp'].copy()
        # TODO: Mismatch between actual URL and issuer ID in SAML response
        for name, url in providers.items():
            if url[-1] != '/':
                providers[name] = url + '/'

        return providers
        
        
    # IExtractionPlugin implementation
    def extractCredentials(self, request):
        """This method performs the PAS credential extraction.
        """
        
        creds={}
        # Initiate challenge
        provider_url = request.form.get("__ac_suisseid_provider_url", None)
        if provider_url is not None and provider_url != "":
            config = self._saml2_config()
            scl = Saml2Client(request.environ, config)
            os.environ['REQUEST_URI'] = request.environ['HTTP_REFERER']

            (sid, result) = scl.authenticate(config['entityid'],
                                             provider_url,
                                             config["service"]["sp"]['url'],
                                             config["service"]["sp"]['name'],
                                             log=logger,
                                             required_attributes=config["service"]["sp"]['required_attributes'],
                                             optional_attributes=config["service"]["sp"]['optional_attributes'])
                           
            if not hasattr(self, '_v_outstanding_authn'):
                self._v_outstanding_authn = {}
            self._v_outstanding_authn[sid] = ''
            
            # Compose POST form with onload submit
            form_body = ''.join(result)
            request.response.setHeader("Content-type", "text/html")
            request.response.setHeader("Content-length", str(len(form_body)))
            request.response.setBody(form_body, lock=True)
            request.response.setStatus(200, lock=True)
            return None
        
        # Idp response
        if 'SAMLResponse' in request.form:
      
            post_env = request.environ.copy()
            post_env['QUERY_STRING'] = ''
        
            request.stdin.seek(0)
            post = cgi.FieldStorage(
                fp = StringIO(request.stdin.read()),
                environ = post_env,
                keep_blank_values = True,
            )
            
            config = self._saml2_config()
            scl = Saml2Client(request.environ, config)
            
            session_info = scl.response(post, config['entityid'], self._v_outstanding_authn, logger)
            ava = session_info['ava'].copy()
            user_id = ava['__userid']
            del ava['__userid']
            
            creds['suisseid.source'] = 'server'
            creds['suisseid.attributes'] = ava
            creds['login'] = user_id
        
        return creds
            
    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):
        if not credentials.has_key("suisseid.source"):
            return None
            
        if credentials['suisseid.source'] == 'server':
            identity = credentials['login']
            
            # Use another plugin to store the credentials
            self._getPAS().updateCredentials(self.REQUEST,
                    self.REQUEST.RESPONSE, identity, "")
              
            # That's Plone specific!!!
            if hasattr(self, 'portal_membership'):
                mt = getToolByName(self, 'portal_membership')
                member = mt.getMemberById(credentials['login'])
                attributes = credentials['suisseid.attributes']
                first_name = attributes.get('First Name', [''])[0]
                last_name = attributes.get('Last Name', [''])[0]
                email = attributes.get('Email', [''])[0]
                fullname = ' '.join((first_name, last_name)).strip()
                properties = {}
                if fullname and not member.getProperty('fullname'):
                    properties['fullname'] = fullname
                if email and not member.getProperty('email'):
                    properties['email'] = email
                member.setMemberProperties(properties)
                    
            return (identity, identity)
            
    # IUserEnumerationPlugin implementation
    def enumerateUsers(self, id=None, login=None, exact_match=False,
            sort_by=None, max_results=None, **kw):
            
        if id and login and id!=login:
            return None

        if (id and not exact_match) or kw:
            return None

        key=id and id or login
        
        if suisseid_format.match(key) is None:
            return None
        
        return [ {
                    "id" : key,
                    "login" : key,
                    "pluginid" : self.getId(),
                } ]
     
    #   
    # ZMI configuration tab
    #    
        
    def _setConfiguration(self, 
                          portal_name='', 
                          portal_url='', 
                          required_attributes='',
                          optional_attributes='', 
                          key_file='', 
                          cert_file='', 
                          xmlsec_binary='/usr/bin/xmlsec1'):
                          
        self.config['portal_name'] = portal_name
        self.config['portal_url'] = portal_url
        self.config['required_attributes'] = required_attributes
        self.config['optional_attributes'] = optional_attributes
        self.config['key_file'] = key_file
        self.config['cert_file'] = cert_file
        self.config['xmlsec_binary'] = xmlsec_binary
        
        self._v_outstanding_authn = {}
        self._v_cached_config = None
        self._p_changed = 1
        
    security.declareProtected(ManageUsers, 'getConfiguration')
    def getConfiguration(self):
        return self.config
        
    security.declareProtected(ManageUsers, 'changeConfiguration')
    def changeConfiguration(self, portal_name, portal_url, required_attributes,
                            optional_attributes, key_file, cert_file, xmlsec_binary):
                            
        self._setConfiguration(portal_name, portal_url, required_attributes, optional_attributes,
                               key_file, cert_file, xmlsec_binary)
        
    security.declareProtected(ManageUsers, 'manage_editConfiguration')
    def manage_editConfiguration(self, REQUEST=None):
        """Form action for editing configuration.
        """
        if not REQUEST:
            return
        form = REQUEST.form
        portal_name = form.get('portal_name', '').strip()
        portal_url = form.get('portal_url', '').strip()
        required_attributes = form.get('required_attributes', [])
        optional_attributes = form.get('optional_attributes', [])
        key_file = form.get('key_file', '')
        cert_file = form.get('cert_file', '')
        xmlsec_binary = form.get('xmlsec_binary', '/usr/bin/xmlsec1')
        
        self.changeConfiguration(portal_name, portal_url, required_attributes, optional_attributes,
                                 key_file, cert_file, xmlsec_binary)
                               
        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/manage_SuisseIDSettings')

    security.declareProtected(ManageUsers, 'manage_SuisseIDSettings')
    manage_SuisseIDSettings = PageTemplateFile(
        os.path.join(_browserdir, 'editSuisseIDSettings'),
        globals(),
        __name__='manage_SuisseIDSettings')

    manage_options = ({
        'label' : 'suisseID Settings',
        'action' : 'manage_SuisseIDSettings'
    },) + BasePlugin.manage_options
        
classImplements(SuisseIDPlugin, IExtractionPlugin, IAuthenticationPlugin, IUserEnumerationPlugin)
