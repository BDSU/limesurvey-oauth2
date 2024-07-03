<?php

use League\OAuth2\Client\Provider\GenericProvider;
use LimeSurvey\PluginManager\AuthPluginBase;
use LimeSurvey\PluginManager\LimesurveyApi;
use LimeSurvey\PluginManager\PluginEvent;
use LimeSurvey\PluginManager\PluginManager;

require_once(__DIR__ . '/vendor/autoload.php');

class AuthOAuth2 extends AuthPluginBase {
	protected const SESSION_STATE_KEY = 'oauth_auth_state';

	protected $storage = 'DbStorage';
	static protected $name = 'OAuth2 Authentication';
	static protected $description = 'Enable Single Sign-On using OAuth2';

	protected $resourceData = [];

	protected $settings = [];

	public function __construct(PluginManager $manager, $id) {
		parent::__construct($manager, $id);

		$this->settings = [
			'client_id' => [
				'type' => 'string',
				'label' => $this->gT('Client ID'),
			],
			'client_secret' => [
				'type' => 'string',
				'label' => $this->gT('Client Secret'),
			],
			'redirect_uri' => [
				'type' => 'info',
				'label' => $this->gT('Redirect URI'),
				'content' => CHtml::tag(
					'input',
					[
						'type' => 'text',
						'class' => 'form-control',
						'readonly' => true,
						'value' => $this->api->createUrl('admin/authentication/sa/login', []),
					]
				),
			],
			'authorize_url' => [
				'type' => 'string',
				'label' => $this->gT('Authorize URL'),
			],
			'scopes' => [
				'type' => 'string',
				'label' => $this->gT('Scopes'),
				'help' => $this->gT('Comma-separated list of scopes to use for authorization.'),
			],
			'access_token_url' => [
				'type' => 'string',
				'label' => $this->gT('Access Token URL'),
			],
			'resource_owner_details_url' => [
				'type' => 'string',
				'label' => $this->gT('User Details URL'),
				'help' => $this->gT('URL to load the user details from using the retrieved access token.'),
			],
			'identifier_attribute' => [
				'type' => 'select',
				'label' => $this->gT('Identifier Attribute'),
				'help' => $this->gT('Attribute of the LimeSurvey user to match against.'),
				'options' => [
					'username' => $this->gT('Username'),
					'email' => $this->gT('E-Mail'),
				],
				'default' => 'username',
			],
			'username_key' => [
				'type' => 'string',
				'label' => $this->gT('Key for username in user details'),
				'help' => $this->gT('Key for the username in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
			],
			'email_key' => [
				'type' => 'string',
				'label' => $this->gT('Key for e-mail in user details'),
				'help' => $this->gT('Key for the e-mail in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
			],
			'display_name_key' => [
				'type' => 'string',
				'label' => $this->gT('Key for display name in user details'),
				'help' => $this->gT('Key for the full name in the user details data. Only required if "Create new users" is enabled.'),
			],
			'is_default' => [
				'type' => 'checkbox',
				'label' => $this->gT('Use as default login'),
				'help' => sprintf(
					'%s<br>%s',
					$this->gT('If enabled instead of showing the LimeSurvey login the user is redirected directly to the OAuth2 login. The default login form can always be accessed via:'),
					htmlspecialchars($this->api->createUrl('admin/authentication/sa/login', ['authMethod' => 'Authdb']))
				),
				'default' => false,
			],
			'autocreate_users' => [
				'type' => 'checkbox',
				'label' => $this->gT('Create new users'),
				'help' => $this->gT('If enabled users that do not exist yet will be created in LimeSurvey after successfull login.'),
				'default' => false,
			],
		];

		if (method_exists(Permissiontemplates::class, 'applyToUser')) {
			$roles = [];
			foreach (Permissiontemplates::model()->findAll() as $role) {
				$roles[$role->ptid] = $role->name;
			}

			$this->settings['autocreate_roles'] = [
				'type' => 'select',
				'label' => $this->gT('Global roles for new users'),
				'help' => $this->gT('Global user roles to be assigned to users that are automatically created.'),
				'options' => $roles,
				'htmlOptions' => [
					'multiple' => true
				],
			];
		}

		$this->settings['autocreate_permissions'] = [
			'type' => 'json',
			'label' => $this->gT('Global permissions for new users'),
			'help' => sprintf(
				$this->gT('A JSON object describing the default permissions to be assigned to users that are automatically created. The JSON object has the follwing form: %s'),
				CHtml::tag('pre', [], "{\n\t\"surveys\": { ... },\n\t\"templates\": {\n\t\t\"create\": false,\n\t\t\"read\": false,\n\t\t\"update\": false,\n\t\t\"delete\": false,\n\t\t\"import\": false,\n\t\t\"export\": false,\n\t},\n\t\"users\": { ... },\n\t...\n}")
			),
			'editorOptions'=>array('mode'=>'tree'),
			'default' => json_encode([
				'users' => [
					'create' => false,
					'read' => false,
					'update' => false,
					'delete' => false,
				],
				'usergroups' => [
					'create' => false,
					'read' => false,
					'update' => false,
					'delete' => false,
				],
				'labelsets' => [
					'create' => false,
					'read' => false,
					'update' => false,
					'delete' => false,
					'import' => false,
					'export' => false,
				],
				'templates' => [
					'create' => false,
					'read' => false,
					'update' => false,
					'delete' => false,
					'import' => false,
					'export' => false,
				],
				'settings' => [
					'read' => false,
					'update' => false,
					'import' => false,
				],
				'surveys' => [
					'create' => false,
					'read' => false,
					'update' => false,
					'delete' => false,
					'export' => false,
				],
				'participantpanel' => [
					'create' => false,
					'read' => false,
					'update' => false,
					'delete' => false,
					'import' => false,
					'export' => false,
				],
				'auth_db' => [
					'read' => false,
				],
			]),
		];
	}

	public function init() {
		$this->subscribe('beforeLogin');
		$this->subscribe('newUserSession');
		$this->subscribe('newLoginForm');
	}

	public function newLoginForm() {
		// we need to add content to be added to the auth method selection
		$this->getEvent()->getContent($this)->addContent('');
	}

	public function beforeLogin() {
		$request = $this->api->getRequest();

		if ($error = $request->getParam('error')) {
			throw new CHttpException(401, $request->getParam('error_description', $error));
		}

		$provider = new GenericProvider([
			'clientId' => $this->get('client_id'),
			'clientSecret' => $this->get('client_secret'),
			'redirectUri' => $this->api->createUrl('admin/authentication/sa/login', []),
			'urlAuthorize' => $this->get('authorize_url'),
			'urlAccessToken' => $this->get('access_token_url'),
			'urlResourceOwnerDetails' => $this->get('resource_owner_details_url'),
			'scopes' => explode(',', $this->get('scopes', null, null, '')),
		]);

		$code = $request->getParam('code');
		$defaultAuth = $this->get('is_default') ? self::class : null;
		if (empty($code) && $request->getParam('authMethod', $defaultAuth) !== self::class) {
			return;
		}

		if (empty($code)) {
			$authorizationUrl = $provider->getAuthorizationUrl();
			Yii::app()->session->add(self::SESSION_STATE_KEY, $provider->getState());

			return $request->redirect($authorizationUrl);
		}

		$state = $request->getParam('state');
		$safedState = Yii::app()->session->get(self::SESSION_STATE_KEY);
		if ($state !== $safedState) {
			throw new CHttpException(401, $this->gT('Invalid state in OAuth response'));
		}

		Yii::app()->session->remove(self::SESSION_STATE_KEY);

		try {
			$accessToken = $provider->getAccessToken('authorization_code', ['code' => $code]);
		} catch (Throwable $exception) {
			throw new CHttpException(401, $this->gT('Failed to retrieve access token'));
		}

		try {
			$resourceOwner = $provider->getResourceOwner($accessToken);
			$this->resourceData = $resourceOwner->toArray();
		} catch (Throwable $exception) {
			throw new CHttpException(401, $this->gT('Failed to retrieve user details'));
		}

		if ($this->get('identifier_attribute') === 'email') {
			$identifierKey = $this->get('email_key');
		} else {
			$identifierKey = $this->get('username_key');
		}

		if (empty($this->resourceData[$identifierKey])) {
			throw new CHttpException(401, $this->gT('User identifier not found or empty'));
		}

		$userIdentifier = $this->resourceData[$identifierKey];
		$this->setUsername($userIdentifier);
		$this->setAuthPlugin();
	}

	public function newUserSession() {
		$userIdentifier = $this->getUserName();
		$identity = $this->getEvent()->get('identity');
		if ($identity->plugin != self::class || $identity->username !== $userIdentifier) {
			return;
		}

		if ($this->get('identifier_attribute') === 'email') {
			$user = $this->api->getUserByEmail($userIdentifier);
		} else {
			$user = $this->api->getUserByName($userIdentifier);
		}

		if (!$user && !$this->get('autocreate_users')) {
			// we don't use setAuthFailure() here because if we are the active auth
			// the error is never shown to the user but instead the user is redirected
			// again, possibly resulting in a redirect loop
			throw new CHttpException(401, $this->gT('User not found in LimeSurvey'));
		}

		if (!$user) {
			$usernameKey = $this->get('username_key');
			$displayNameKey = $this->get('display_name_key');
			$emailKey = $this->get('email_key');
			if (empty($this->resourceData[$usernameKey]) || empty($this->resourceData[$displayNameKey]) || empty($this->resourceData[$emailKey])) {
				throw new CHttpException(401, $this->gT('User data is missing required attributes to create new user'));
			}

			$user = new User();
			$user->parent_id = 1;
			$user->setPassword(createPassword());

			$user->users_name = $this->resourceData[$usernameKey];
			$user->full_name = $this->resourceData[$displayNameKey];
			$user->email = $this->resourceData[$emailKey];

			if (!$user->save()) {
				throw new CHttpException(401, $this->gT('Failed to create new user'));
			}

			$defaultPermissions = json_decode($this->get('autocreate_permissions', null, null, []), true);
			if (!empty($defaultPermissions)) {
				Permission::setPermissions($user->uid, 0, 'global', $defaultPermissions, true);
			}

			if (method_exists(Permissiontemplates::class, 'applyToUser')) {
				$autoCreateRoles = (array) $this->get('autocreate_roles', null, null, []);
				foreach ($autoCreateRoles as $role) {
					Permissiontemplates::model()->applyToUser($user->uid, $role);
				}
			}
		}

		$this->setUsername($user->users_name);
		$this->setAuthSuccess($user);
	}
}
