<?php
/**
 * @package     Joomla
 * @copyright   Copyright (C) 2019 Hugo Moracchini. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @author      Hugo Moracchini
 */

// No direct access
defined('_JEXEC') or die('Restricted access');

jimport('joomla.plugin.plugin');
/**
 * Joomla User plugin
 *
 * @package     Joomla.Plugin
 * @subpackage  User
 * @since       3.8.13
 */
class plgAuthenticationCciconnect_Oauth2 extends JPlugin {


	/**
	 * @var  string  The authorisation url.
	 */
	protected $authUrl;
	/**
	 * @var  string  The access token url.
	 */
	protected $tokenUrl;
	/**
	 * @var  string  The REST request domain.
	 */
	protected $domain;
	/**
	 * @var  string[]  Scopes available based on mode settings.
	 */
	protected $scopes;
	/**
	 * @var string The email subject.
	 */
	protected $email_subject;
	/**
	 * @var string The email body (in HTML).
	 */
	protected $email_body;


	public function __construct(&$subject, $config) {
		parent::__construct($subject, $config);
		$this->loadLanguage();
		$this->scopes = explode(',', $this->params->get('scopes', 'openid'));
		$this->authUrl = $this->params->get('auth_url');
		$this->domain = $this->params->get('domain');
		$this->tokenUrl = $this->params->get('token_url');
		$this->email_subject = $this->params->get('email_subject', 'You have successfully registeted using CCIConnect.');
		$this->email_body = $this->params->get('email_body', '<h1>Error</h1><p>Please configure an email body in the configuration settings.</p>');
	}



	/**
	 * Handles authentication via the OAuth2 client.
	 *
	 * @param   array  $credentials Array holding the user credentials
	 * @param   array  $options     Array of extra options
	 * @param   object &$response   Authentication response object
	 *
	 * @return  boolean
	 * @throws Exception
	 */
	public function onUserAuthenticate($credentials, $options, &$response) {

		$response->type = 'OAuth2';

		if ($options['action'] == 'core.login.site') {

			$username = $credentials['username'];
			if (!$username) {
				$response->status = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
				return false;
			}

			try {

				$token = $options['token'];
				$url = $this->params->get('sso_account_url');
				$oauth2 = new JOAuth2Client;
				$oauth2->setToken($token);
				$result = $oauth2->query($url);

				$body = json_decode($result->body);
				$response->email = $body->email;
				$response->fullname = $body->name;
				$response->firstname = $body->given_name;
				$response->lastname = $body->family_name;
				$response->username = $body->preferred_username;
				$response->status = JAuthentication::STATUS_SUCCESS;
				$response->isnew = empty(JUserHelper::getUserId($body->preferred_username));
				$response->error_message = '';

				if ($user = new JUser(JUserHelper::getUserId($body->preferred_username)) && ($user->get('block') || $user->get('activation'))) {
					$response->status = JAuthentication::STATUS_FAILURE;
					$response->error_message = JText::_('JGLOBAL_AUTH_ACCESS_DENIED');
					return;
				}

			} catch (Exception $e) {
				// log error.
				$response->status = JAuthentication::STATUS_FAILURE;
				return false;
			}
		}
	}



	/**
	 * Authenticate the user via the oAuth2 login and authorise access to the
	 * appropriate REST API end-points.
	 */
	public function onOauth2Authenticate() {
		$oauth2 = new JOAuth2Client;
		$oauth2->setOption('authurl', $this->authUrl);
		$oauth2->setOption('clientid', $this->params->get('client_id'));
		$oauth2->setOption('scope', $this->scopes);
		$oauth2->setOption('redirecturi', $this->params->get('redirect_url'));
		$oauth2->setOption('requestparams', array('access_type'=>'offline', 'approval_prompt'=>'auto'));
		$oauth2->setOption('sendheaders', true);
		$oauth2->authenticate();
	}



	/**
	 * Swap the authorisation code for a persistent token and authorise access
	 * to Joomla!.
	 *
	 * @return  bool  True if the authorisation is successful, false otherwise.
	 * @throws Exception
	 */
	public function onOauth2Authorise() {

		// Build HTTP POST query requesting token.
		$oauth2 = new JOAuth2Client;
		$oauth2->setOption('tokenurl', $this->tokenUrl);
		$oauth2->setOption('clientid', $this->params->get('client_id'));
		$oauth2->setOption('clientsecret', $this->params->get('client_secret'));
		$oauth2->setOption('redirecturi', $this->params->get('redirect_url'));
		$result = $oauth2->authenticate();

		// We insert a temporary username, it will be replaced by the username retrieved from the OAuth system.
		$credentials = array();
		$credentials['username']  = 'temporary_username';

		// Adding the token to the login options allows Joomla to use it for logging in.
		$options = array();
		$options['token']  = $result;
		$options['provider'] = 'cciconnect';

		$app = JFactory::getApplication();

		// Perform the log in.
		return $app->login($credentials, $options) === true;
	}



	/**
	 * After the login has been executed, we need to send the user an email.
	 *
	 * @param Spread The user info comes in the form of multiple params which 
	 * are concatenanted to an array using the PHP spread operator (...).
	 * @return  bool  True if the email is successfully sent, false if not.
	 */
	public function onOAuthAfterRegister(...$user_info) {

		$user = [
			'username' => $user_info[3],
			'email' => $user_info[5],
			'name' => $user_info[6]
		];

		$config = JFactory::getConfig();

		// Set sender
		$sender = [
			$config->get('mailfrom'),
			$config->get('fromname')
		];

		$post = [
			'USER_NAME'     => $user['fullname'],
			'SITE_URL'      => JURI::base(),
			'USER_EMAIL'    => $user['email'],
			'USERNAME'      => $user['username'],
			'SITE_NAME'     => $config->get('sitename'),
		];

		// Handle [] in post keys.
		$keys = [];
		foreach (array_keys($post) as $key) {
			$keys[] = '/\['.$key.'\]/';
		}


		// Tags are replaced with their corresponding values using the PHP preg_replace function.
		$subject = preg_replace($keys, $post, $this->email_subject);
		$body = preg_replace($keys, $post, $this->email_body);
		

		// Configure email sender
		$mailer = JFactory::getMailer();
		$mailer->setSender($sender);
		$mailer->addReplyTo($mail_from, $mail_from_name);
		$mailer->addRecipient($user['email']);
		$mailer->setSubject($subject);
		$mailer->isHTML(true);
		$mailer->Encoding = 'base64';
		$mailer->setBody($body);

		// Send and log the email.
		$send = $mailer->Send();

		if ($send !== true) {

			JLog::add($send->__toString(), JLog::ERROR, 'plg_cciconnect');
			return false;

		} else {
			$app = JFactory::getApplication();
			$app->enqueueMessage(JText::_('PLG_AUTHENTICATION_CCICONNECT_OAUTH2_SIGNED_IN'));
			return true;
		}
	}

}
