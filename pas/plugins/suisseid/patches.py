from saml2 import client
from saml2 import config
from saml2 import BINDING_HTTP_POST

# Patch saml2 so that binding is post and not redirect
def entity_id2url(meta, entity_id):
    """ Grab the first endpoint if there are more than one, 
        raises IndexError if the function returns an empty list.
     
    :param meta: MetaData instance
    :param entity_id: The entity id of the entity for which an
        endpoint is sought
    :return: An endpoint (URL)
    """
    return meta.single_sign_on_services(entity_id, binding = BINDING_HTTP_POST)[0]
    
config.entity_id2url = entity_id2url

# Patch saml2 so that Name is alway used instead of FriendlyName for attributes
def get_attribute_values(attribute_statement):
    """ Get the attributes and the attribute values 
    
    :param response: The AttributeStatement.
    :return: A dictionary containing attributes and values
    """
    
    result = {}
    for attribute in attribute_statement.attribute:
        name = attribute.name.strip()
        result[name] = []
        for value in attribute.attribute_value:
            if not value.text:
                result[name].append('')
            else:
                result[name].append(value.text.strip())    
    return result
    
client.get_attribute_values = get_attribute_values