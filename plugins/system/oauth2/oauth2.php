<?php
/**
 * @package     OAuth2
 *
 * @copyright   Copyright (C) 2019 Hugo Moracchini All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('_JEXEC') or die;

/**
 * A system plugin which routes OAuth2 requests to their respective custom plugins.
 *
 * @package  OAuth2
 */
class PlgSystemOauth2 extends JPlugin {

	/**
	 * This plugin calls OAuth2 events if we are trying to login/register via OAuth2.
	 *
	 * @return  void
	 * @throws Exception
	 */
	public function onAfterRoute() {

		$app = JFactory::getApplication();

		JPluginHelper::importPlugin('authentication');
		$dispatcher = JEventDispatcher::getInstance();

		$uri = clone JUri::getInstance();
		$queries = $uri->getQuery(true);

		$task = $queries['task'];

		if ($task == 'oauth2.authenticate') {

			$data = $app->getUserState('users.login.form.data', array());
			$data['return'] = $app->input->get('return', null);
			$app->setUserState('users.login.form.data', $data);
			$dispatcher->trigger('onOauth2Authenticate', array());

		} else {
			
			if (!empty($queries['session_state']) && !empty($queries['code'])) {
				
				$array = $dispatcher->trigger('onOauth2Authorise', array());

				// redirect user based on a return value if present.
				if ($array[0] === true) {

					$data = $app->getUserState('users.login.form.data', array());
					$app->setUserState('users.login.form.data', array());

					if ($return = $data['return'])
						$app->redirect(JRoute::_(base64_decode($return), false));
					else
						$app->redirect(JRoute::_(JUri::current(), false));

				} else {
					$app->redirect(JRoute::_('index.php?option=com_users&view=login', false));
				}
			}
		}
	}
}