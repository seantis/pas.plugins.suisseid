from AccessControl.Permissions import manage_users as ManageUsers
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin

import plugin
registerMultiPlugin(plugin.SuisseIDPlugin.meta_type)

def initialize(context):
    # TODO: Condition on saml2 import
    context.registerClass(plugin.SuisseIDPlugin,
                            permission=ManageUsers,
                            constructors=
                                    (plugin.manage_addSuisseIDPlugin,
                                     plugin.addSuisseIDPlugin),
                            visibility=None,
                            icon="www/suisseid.png")

