# Configure LimeSurvey login with Azure AD

Using this plugin Microsoft Azure Active Directory can be used to login into LimeSurvey,
i.e. with a Microsoft365 account.

## Register a new App in Azure AD

Follow [this guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
to register a new app in Azure AD for LimeSurvey. The correct _Redirect URI_ for LimeSurvey can be found
in the plugin configuration.

From the overview page In Azure AD then copy the _Client ID_/"Application ID" and from the endpoints overview
the _Authorize URL_ and _Access Token URL_ can be copied.

Create a new _Client Secret_ for the Azure AD app and copy it into the plugin configuration.

Ensure that the [granted permissions](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis)
include the [`User.Read` permission](https://docs.microsoft.com/en-us/graph/permissions-reference#delegated-permissions-73).

The plugin configuration so far should look like this:

| Option           | Value                                                           |
|------------------|-----------------------------------------------------------------|
| Client ID        | 4e921cb2-1d8e-460d-a1f6-1b4c549d9361                            |
| Client Secret    | your_beloved_secret                                            |
| Authorize URL    | https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize |
| Scopes           | User.Read                                                       |
| Access Token URL | https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token    |

## Configure User Details

With the retrieved access token LimeSurvey can then fetch the user details using the
[`/me` endpoint of the Microsoft Graph API](https://docs.microsoft.com/en-us/graph/api/user-get).
This will return the user profile in a flat JSON object for which the following keys
can then be configured for the plugin:


| Option                               | Value                               |
|--------------------------------------|-------------------------------------|
| User Details URL                     | https://graph.microsoft.com/v1.0/me |
| Key for username in user details     | mail                                |
| Key for e-mail in user details       | mail                                |
| Key for display name in user details | displayName                         |

This will use the e-mail for both: the LimeSurvey username and the e-mail.

## Restrict access to specific users

Following [this guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-restrict-your-app-to-a-set-of-users)
you can restrict access to the LimeSurvey App in Azure AD and thus who can login to LimeSurvey with it.

You can either assign users to the app manually or use an existing security group.
