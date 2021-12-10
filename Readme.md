# What is this

This is an authentication plugin for [LimeSurvey](https://github.com/LimeSurvey/LimeSurvey)
enabling Single Sign-On with any identity provider using the OAuth2 protocol.

It uses the [`league/oauth2-client` library](https://github.com/thephpleague/oauth2-client)
and can be configured for any identity provider that supports OAuth2 with the
_authorization code grant_ flow and supports automatic creation of new users.

# Installation

- go to [releases](https://github.com/BDSU/limesurvey-oauth2/releases) and download the latest release Zip archive
- for LimeSurvey 5.x: upload the Zip archive in the plugin manager
- for LimeSurvey 3.x: extract the Zip archive and place the contents in `<limesurvey_root>/plugins/AuthOAuth2/`
- configure the plugin in the plugin manager
- activate the plugin in the plugin manager

To test the latest development version `git clone` [this repository](https://github.com/BDSU/limesurvey-oauth2)
into `<limesurvey_root>/plugins/AuthOAuth2/` and run `composer install` in it to download all dependencies.

# Configuration

Before activating the plugin open its configuration from the plugin manager.

With your identity provider create a new app for LimeSurvey and paste the _Redirect URI_ shown in the
LimeSurvey configuration there. Fill in the _Client ID_, _Client Secret_, _Authorize URL_, _Scopes_ and
_Access Token URL_ into the plugin configuration according to the documentation of your identity provider.

The _User Details URL_ should point to an API endpoint that provides a JSON object with details on the
current user using the retrieved access token. The details should include a unique username, the e-mail
address and a display name. Further below you can specify the keys of the JSON object containing these details.

With the _Identifier Attribute_ you can configure whether users should be matched using the _username_ or the
_e-mail_ with existing users in the LimeSurvey database. If _Create new users_ is enabled new LimeSurvey users
will automatically be created if they can not be found in the database. You can configure permissions and
(starting with LimeSurvey 4.x) user roles that will be automatically assigned to all created users.

If _Use as default login_ is enabled instead of showing the LimeSurvey login form users will be redirected
to the configured OAuth2 identity provider and logged in automatically on success. Otherwise the user has to
select OAuth2 as authentication method manually.

Below the _Use as default login_ checkbox a URL is shown with which the default login form can always be accessed
to login using the internal database even when automatic redirection is enabled.

You can find [a configuration example for Azure Active Directory here](docs/examples/AzureAD.md).

# Supported LimeSurvey Versions

This plugin was tested with

- the latest stable release v5.2.5
- the latest LTS release v3.27.28

and should work with all version 3.x or newer.
Configuring user roles for new users is only supported starting with LimeSurvey 4.x.

The minimum required PHP version is 5.6.
