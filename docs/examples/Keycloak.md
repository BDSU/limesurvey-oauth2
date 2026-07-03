# Configure LimeSurvey login with Keycloak

Using this plugin Keycloak can be used to login into LimeSurvey.

## Register a new App in Keycloak

Create a new client with secret on Keycloak  
The plugin configuration so far should look like this:

| Option           | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Client ID        | limesurvey                                                           |
| Client Secret    | your_beloved_secret                                                  |
| Authorize URL    | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/auth  |
| Scopes           | email,profile,openid                                                 |
| Separator        | space_character for Keycloak                                         |
| Access Token URL | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/token |

## Configure User Details

With the retrieved access token LimeSurvey can then fetch the user details.
This will return the user profile in a flat JSON object for which the following keys
can then be configured for the plugin:


| Option                               | Value                                                                   |
|--------------------------------------|-------------------------------------------------------------------------|
| User Details URL                     | https://auth.ulysseus.eu/realms/master/protocol/openid-connect/userinfo |
| Key for username in user details     | given_name.first_letter+family_name.lower_case                          |
| Key for e-mail in user details       | email                                                                   |
| Key for display name in user details | given_name.capitalize+family_name.upper_case                            |

We have coded few templating functions to make your user name and display name more customizable, you're free to extend it.
