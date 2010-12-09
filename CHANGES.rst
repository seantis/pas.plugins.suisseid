Changelog
=========

0.1b3 (2010-12-09)
------------------

- Make sure that the challenge initiation and response handling happen
  on the configured URL only (allows other suisseId handlers on other URLs).
- Patch pySAML2's audience restriction check so that only the first part of 
  the URL has to be the same.

0.1b2 (2010-12-07)
------------------

- Cleanup docs
- Cleanup metadata.xml file
- Change SwissSign Idp endpoint URL
- Show SAML2 metadata file configuration option
- Patch pySAML2 so that POST is default binding in metadata configuration
- Use Name instead of FriendlyName for core/derived assertion attributes

0.1b1 (2010-10-22)
------------------

- Initial release
