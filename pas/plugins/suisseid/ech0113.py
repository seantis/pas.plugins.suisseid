from saml2 import SamlBase
from saml2.saml import Attribute, NAMESPACE

class ExtendedAttribute(Attribute):

    c_tag = 'Attribute'
    c_namespace = NAMESPACE
    c_children = Attribute.c_children.copy()
    c_attributes = Attribute.c_attributes.copy()
    c_attributes['eCH-0113:required'] = 'required'
    
    def __init__(self, name=None, name_format=None, friendly_name=None,
                 attribute_value=None, text=None, extension_elements=None,
                 extension_attributes=None, required=False):
                 
        super(ExtendedAttribute, self).__init__(name, name_format, friendly_name,
                                                attribute_value, text, extension_elements,
                                                extension_attributes)
                                                
        self.required = required
        
        
    def _to_element_tree(self):
        element = super(ExtendedAttribute, self)._to_element_tree()
        # We have to define the namespace prefix "eCH-0113" which is used by the "required" attribute
        element.attrib['xmlns:eCH-0113'] = "http://www.ech.ch/xmlns/eCH-0113/1"
        return element
        
        
class PrivacyNotice(SamlBase):
        
    c_tag = 'PrivacyNotice'
    c_namespace = 'http://schemas.xmlsoap.org/ws/2005/05/identity'
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_attributes['Version'] = 'version'
    
    def __init__(self, text=None, extension_elements=None, extension_attributes=None, version='1'):
        super(PrivacyNotice, self).__init__(text, extension_elements, extension_attributes)
        self.version = version
        
    def _to_element_tree(self):
        element = super(PrivacyNotice, self)._to_element_tree()
        # Type element is required (even though it's not in the specification)
        element.attrib['xmlns:xsi'] = "http://www.w3.org/2001/XMLSchema-instance"
        element.attrib['xsi:type'] = "ns1:PrivacyNoticeLocationType"
        return element