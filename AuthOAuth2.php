<?php

use League\OAuth2\Client\Provider\GenericProvider;
use LimeSurvey\PluginManager\AuthPluginBase;
use LimeSurvey\PluginManager\LimesurveyApi;
use LimeSurvey\PluginManager\PluginEvent;

require_once(__DIR__ . '/vendor/autoload.php');

class AuthOAuth2 extends AuthPluginBase {
	protected const SESSION_STATE_KEY = 'oauth_auth_state';

	protected $storage = 'DbStorage';
	static protected $name = 'OAuth2 Authentication';
	static protected $description = 'Enable Single Sign-On using OAuth2';

	protected $settings = [
		'client_id' => [
			'type' => 'string',
			'label' => 'Client ID',
		],
		'client_secret' => [
			'type' => 'string',
			'label' => 'Client Secret',
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
		'username_key' => [
			'type' => 'string',
			'label' => 'Key for username in user details',
		],
	];

	public function init() {
		$this->subscribe('beforeLogin');
		$this->subscribe('newUserSession');
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
			$resourceData = $resourceOwner->toArray();
		} catch (Throwable $exception) {
			throw new CHttpException(401, 'Failed to retrieve user details');
		}

		$identifierKey = $this->get('username_key');
		if (empty($resourceData[$identifierKey])) {
			throw new CHttpException(401, 'User identifier not found or empty');
		}

		$username = $resourceData[$identifierKey];
		$this->setUsername($username);
		$this->setAuthPlugin();
	}

	public function newUserSession() {
		$identity = $this->getEvent()->get('identity');
		if ($identity->plugin != self::class) {
			return;
		}

		$username = $this->getUserName();
		$user = $this->api->getUserByName($username);
		if (!$user) {
			// we don't use setAuthFailure() here because if we are the active auth
			// the error is never shown to the user but instead the user is redirected
			// again, possibly resulting in a redirect loop
			throw new CHttpException(401, 'User not found in LimeSurvey');
		}

		$this->setAuthSuccess($user);
	}
}
