<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * CodeIgniter ACL Class
 *
 * ACL library for CodeIgniter Framework
 *
 * @package		CodeIgniter
 * @subpackage	Libraries
 * @category	Libraries
 * @author 		David Brandes <david.brandes at gmail.com>
 * @link 		https://github.com/brandesign/CodeIgniter-ACL
 * @copyright 	Copyright (c) 2012, David Brandes
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

class Acl_auth
{
	/**
	 * List of all errors
	 *
	 * @var array
	 */
	private $_errors = array();
	private $_config;

	public function __construct()
	{
		$this->load->config('acl_auth', TRUE);
		$this->_config = $this->config->item('acl_auth');
		$this->load->library( array( 'email', 'session', 'phpass' ) );
		$this->load->helper('cookie');
		$this->load->model( $this->_config['user_model'], 'user_model' );
		$this->lang->load('acl_auth');
		if( ! $this->logged_in() && get_cookie('identity') && get_cookie('remember_code') )
		{
			$this->login_remembered();
		}
	}

	/**
	* __get
	*
	* Enables the use of CI super-global without having to define an extra variable.
	*
	* @access public
	* @param $var
	* @return mixed
	*/
	public function __get( $var )
	{
		return get_instance()->$var;
	}

	/**
	 * register a new user
	 *
	 * @access public
	 * @param array
	 * @return bool
	 * @todo set error messages
	 **/
	public function register( $data )
	{
		if( ! array_key_exists( $this->_config['identity_field'], $data ) OR ! array_key_exists( $this->_config['password_field'], $data ) )
		{
			$this->set_error( 'register_failed' );
			return false;
		}

		$insert = array();

		foreach( $data as $field => $value )
		{
			if( $field == $this->_config['password_field'] )
			{
				$value = $this->phpass->hash( $value );
			}
			if( $this->user_model->field_exists( $field ) )
			{
				$insert[$field] = $value;
			}
		}

		if( $id = $this->user_model->insert( $insert ) )
		{
			$this->login( $data['email'], $data['password'], TRUE );
			return true;
		}
		else
		{
			$this->set_error('register_failed');
			return false;
		}
	}

	/**
	 * login
	 *
	 * @access public
	 * @param string
	 * @param string
	 * @return bool
	 **/
	public function login( $identity, $password, $remember = FALSE, $session_data = array() )
	{
		$user = $this->user_model->get_user( $identity );

		if( ! $user OR ! $this->phpass->check( $password, $user->password ) )
		{
			$this->set_error( 'login_failed' );
			return false;
		}

		$session = array(
			'user_id'	=> $user->id
			,'logged_in'=> TRUE
			,'user_'.$this->_config['identity_field'] => $user->{$this->_config['identity_field']}
		);

		foreach( $session_data as $key )
		{
			$session['user_'.$key] = ( $user->$key ) ? $user->$key : NULL;
		}

		$this->session->set_userdata( $session );

		if( $remember )
		{
			$remember_code = $this->phpass->hash(uniqid());
			$this->user_model->update( $user->id, array('remember_code' => $remember_code) );
			$expire = (60*60*24*365*2);
			set_cookie(array(
			    'name'   => 'identity',
			    'value'  => $identity,
			    'expire' => $expire
			));

			set_cookie(array(
			    'name'   => 'remember_code',
			    'value'  => $remember_code,
			    'expire' => $expire
			));
		}
		return true;
	}

	private function login_remembered()
	{
		$identity = get_cookie('identity');
		$code 	  = get_cookie('remember_code');
		$user = $this->user_model->get_by( array($this->_config['identity_field'] => $identity) );
		if( $user && $user->remember_code === $code )
		{
			$session = array(
				'user_id'	=> $user->id
				,'logged_in'=> TRUE
				,'user_'.$this->_config['identity_field'] => $user->{$this->_config['identity_field']}
			);
			$this->session->set_userdata($session);
		}
	}

	/**
	 * logout
	 *
	 * @access public
	 * @return bool
	 **/
	public function logout()
	{
		$this->session->sess_destroy();
		delete_cookie('identity');
		delete_cookie('remember_code');
		$this->session->sess_create();
		return( TRUE === $this->session->userdata('logged_in') ) ? false : true;
	}

	/**
	 * is the user logged in?
	 *
	 * @access public
	 * @return bool
	 **/
	public function logged_in()
	{
		return (bool) $this->session->userdata('logged_in');
	}

	/**
	 * Send password reset
	 *
	 * @access public
	 * @param string
	 * @return bool
	 **/
	public function send_password_reset( $identity )
	{
		$user = $this->user_model->get_user( $identity );

		if( ! $user )
		{
			$this->set_error( 'reset_user_not_found' );
			return false;
		}

		$reset_code = $this->_reset_code();
		$update = array(
			'reset_code' => $reset_code
			,'reset_time'=>	time()
		);

		$this->user_model->update( $user->id, $update );

		$data = array(
			'user'	=> $user
			,'reset_code' => $reset_code
		);

		$message = $this->load->view( $this->_config['reset_template'], $data, TRUE );

		$this->email->from( $this->_config['admin_mail'], $this->_config['admin_name'] );
        $this->email->to( $user->email );

        $this->email->subject( $this->_config['reset_subject'] );
        $this->email->message( $message );

        return ( $this->email->send() ) ? true : false;

        //echo $this->email->print_debugger();
	}

	/**
	 * Check if reset token is valid
	 *
	 * @access public
	 * @param string
	 * @param string
	 * @return bool
	 **/
	public function check_reset_token( $identity, $token )
	{
		$user = $this->user_model->get_user( $identity );
		if( !$user )
		{
			$this->set_error( 'reset_user_not_found' );
			return false;
		}

		if( ( time() - $user->reset_time ) > 1200 )
		{
			$this->set_error( 'reset_token_expired' );
			return false;
		}

		if( $user->reset_code === $token )
		{
			return true;
		}
		$this->set_error( 'reset_token_check_failed' );
		return false;
	}

	/**
	 * Confirm password reset
	 *
	 * @access public
	 * @param string
	 * @param string
	 * @param string
	 * @return bool
	 **/
	public function set_new_password( $identity, $token, $newpass )
	{
		$user = $this->user_model->get_user( $identity );
		if( ! $user OR ! $this->check_reset_token( $identity, $token ) )
		{
			$this->set_error( 'reset_user_not_found' );
			return false;
		}

		$data = array(
			'reset_code' => NULL
			,'reset_time'=> NULL
			,$this->_config['password_field'] => $this->phpass->hash( $newpass )
		);

		if( $this->user_model->update( $user->id, $data ) )
		{
			$session = array();
			foreach( $user as $k => $v )
			{
				$session[] = $k;
			}
			$this->login( $identity, $newpass, $session );
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	 * generate reset code
	 *
	 * @access private
	 * @return string
	 **/
	private function _reset_code()
	{
		$ret = '';
		for( $x = 0; $x < 32; $x++ )
		{
			$chars = array(
				chr( mt_rand( 48, 57 ) )
				,chr( mt_rand( 64, 90 ) )
				,chr( mt_rand( 97, 122 ) )
			);
        	//$ret .= chr( mt_rand( 0, 255 ) );
        	$ret .= $chars[array_rand($chars)];
    	}
    	return $ret;
	}

	/**
	 * Checks if a user has a role
	 *
	 * @access public
	 * @param int
	 * @param string
	 * @return bool
	 **/
	public function has_role( $role, $user_id = NULL )
	{
		if( is_null( $user_id ) )
		{
			$user_id = $this->session->userdata('user_id');
		}
		return (bool) $this->user_model->has_role( $user_id, $role );
	}

	/**
	 * Act if user has no access
	 *
	 * @access public
	 * @param string
	 * @param array
	 * @return void
	 * @todo allow to set some actions on denied access
	 **/
	public function restrict_access( $role, $actions = array() )
	{
		$has_role 	= false;
		switch ( $role )
		{
			case 'guest':
				$has_role = true;
				break;
			case 'logged_in':
				if( $this->logged_in() )
				{
					$has_role = true;
				}
				break;
			default:
				if( $this->logged_in() )
				{
					$has_role = $this->has_role( $role );
				}
				break;
		}
		
		if( ! $has_role )
		{
			if( ! $this->logged_in() )
			{
				//THIS IS DEFAULT
				if( strlen($this->_config['401_login_page']) > 0 )
				{
					redirect( $this->_config['401_login_page'] );
				}
				else if( strlen($this->_config['401_override']) > 0 )
				{
					redirect( $this->_config['401_override'] );
				}
				else
				{
					show_error('Unauthorized', 401 );
				}
			}
			else
			{
				//THIS IS DEFAULT
				if( strlen($this->_config['401_override']) > 0 )
				{
					redirect( $this->_config['401_override'] );
				}
				else
				{
					show_error('Unauthorized', 401 );
				}
			}
		}
	}

	/**
	 * Set error message
	 *
	 * @access private
	 * @param string
	 * @return void
	 **/
	private function set_error( $error )
	{
		$this->_errors[] = $error;
	}

	/**
	 * Get error messages
	 *
	 * @access public
	 * @return array
	 **/
	public function errors()
	{
		foreach ( $this->_errors as $key => $error )
		{
			$this->_errors[$key] = $this->lang->line( $error ) ? $this->lang->line( $error ) : '##' . $error . '##';
		}
		return $this->_errors;
	}
}