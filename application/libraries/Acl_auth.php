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
	protected $errors;

	public function __construct()
	{
		$this->load->config('acl_auth', TRUE);
		$this->load->library( array( 'email', 'session', 'phpass' ) );
		//$this->load->helper('cookie');
		$this->load->model('User_model');

		$this->errors = array();
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
		if( ! array_key_exists( $this->config->item( 'identity_field', 'acl_auth' ), $data ) OR ! array_key_exists( $this->config->item( 'password_field', 'acl_auth' ), $data ) )
		{
			$this->set_error( 'register_failed' );
			return false;
		}

		$insert = array();

		foreach( $data as $field => $value )
		{
			if( $field == $this->config->item( 'password_field', 'acl_auth' ) )
			{
				$value = $this->phpass->hash( $value );
			}
			if( $this->User_model->field_exists( $field ) )
			{
				$insert[$field] = $value;
			}
		}

		if( $id = $this->User_model->insert( $insert ) )
		{
			$this->login( $data['email'], $data['password'] );
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
	public function login( $user, $password, $session_data = array() )
	{
		$identity_field = $this->config->item('identity_field', 'acl_auth');
		$count = $this->User_model->count_by( $identity_field, $user );
		if( $count > 1 )
		{
			$this->set_error( 'error_multiple_accounts' );
			return false;
		}

		$user = $this->User_model->get_by( $identity_field, $user );

		if( ! $this->phpass->check( $password, $user->password ) )
		{
			$this->set_error( 'login_failed' );
			return false;
		}
		else
		{
			$session = array(
				'user_id'	=> $user->id
				,'logged_in'=> TRUE
			);

			foreach( $session_data as $key )
			{
				$session['user_'.$key] = ( $user->$key ) ? $user->$key : NULL;
			}

			$this->session->set_userdata( $session );
			return true;
		}
		return false;
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
		return (bool) $this->User_model->has_role( $user_id, $role );
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
				set_status_header( 401 );
				redirect('/auth');
			}
			else
			{
				show_error('Unauthorized', 401 );
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
		$this->errors[] = $error;
	}

	/**
	 * Get error messages
	 *
	 * @access public
	 * @return array
	 **/
	public function errors()
	{
		return $this->errors;
	}
}