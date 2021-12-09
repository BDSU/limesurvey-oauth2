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
				'label' => 'Client ID',
			],
			'client_secret' => [
				'type' => 'string',
				'label' => 'Client Secret',
			],
			'redirect_uri' => [
				'type' => 'info',
				'label' => 'Redirect URI',
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
				'label' => 'Authorize URL',
			],
			'scopes' => [
				'type' => 'string',
				'label' => 'Scopes',
				'help' => 'Comma-separated list of scopes',
			],
			'access_token_url' => [
				'type' => 'string',
				'label' => 'Access Token URL',
			],
			'resource_owner_details_url' => [
				'type' => 'string',
				'label' => 'User Details URL',
			],
			'identifier_attribute' => [
				'type' => 'select',
				'label' => 'Identifier Attribute',
				'options' => [
					'username' => 'Username',
					'email' => 'E-Mail',
				],
				'default' => 'username',
			],
			'username_key' => [
				'type' => 'string',
				'label' => 'Key for username in user details',
			],
			'email_key' => [
				'type' => 'string',
				'label' => 'Key for e-mail in user details',
			],
			'display_name_key' => [
				'type' => 'string',
				'label' => 'Key for display name in user details',
			],
			'is_default' => [
				'type' => 'checkbox',
				'label' => 'Use as default login',
				'default' => false,
			],
			'autocreate_users' => [
				'type' => 'checkbox',
				'label' => 'Create new users',
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
				'label' => 'Global roles for new users',
				'options' => $roles,
				'htmlOptions' => [
					'multiple' => true
				],
			];
		}

		$this->settings['autocreate_permissions'] = [
			'type' => 'json',
			'label' => 'Global permissions for new users',
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
			throw new CHttpException(401, 'Invalid state in OAuth response');
		}

		Yii::app()->session->remove(self::SESSION_STATE_KEY);

		try {
			$accessToken = $provider->getAccessToken('authorization_code', ['code' => $code]);
		} catch (Throwable $exception) {
			throw new CHttpException(401, 'Failed to retrieve access token');
		}

		try {
			$resourceOwner = $provider->getResourceOwner($accessToken);
			$this->resourceData = $resourceOwner->toArray();
		} catch (Throwable $exception) {
			throw new CHttpException(401, 'Failed to retrieve user details');
		}

		if ($this->get('identifier_attribute') === 'email') {
			$identifierKey = $this->get('email_key');
		} else {
			$identifierKey = $this->get('username_key');
		}

		if (empty($this->resourceData[$identifierKey])) {
			throw new CHttpException(401, 'User identifier not found or empty');
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
			throw new CHttpException(401, 'User not found in LimeSurvey');
		}

		if (!$user) {
			$usernameKey = $this->get('username_key');
			$displayNameKey = $this->get('display_name_key');
			$emailKey = $this->get('email_key');
			if (empty($this->resourceData[$usernameKey]) || empty($this->resourceData[$displayNameKey]) || empty($this->resourceData[$emailKey])) {
				throw new CHttpException(401, 'User data is missing required attributes to create new user');
			}

			$user = new User();
			$user->parent_id = 1;
			$user->setPassword(createPassword());

			$user->users_name = $this->resourceData[$usernameKey];
			$user->full_name = $this->resourceData[$displayNameKey];
			$user->email = $this->resourceData[$emailKey];

			if (!$user->save()) {
				throw new CHttpException(401, 'Failed to create new user');
			}

			$defaultPermissions = json_decode($this->get('autocreate_permissions', null, null, []), true);
			if (!empty($defaultPermissions)) {
				Permission::setPermissions($user->uid, 0, 'global', $defaultPermissions, true);
			}

			if (method_exists(Permissiontemplates::class, 'applyToUser')) {
				foreach ($this->get('autocreate_roles', null, null, []) as $role) {
					Permissiontemplates::model()->applyToUser($user->uid, $role);
				}
			}
		}

		$this->setUsername($user->users_name);
		$this->setAuthSuccess($user);
	}
}
