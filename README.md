CodeIgniter-ACL
===============

A small ACL library for CodeIgniter Framework using Jamie Rumbelow's MY_Model (http://github.com/jamierumbelow/codeigniter-base-model)

#### This library should not be used in production environment. You can help to make it stable!

Installation
------------

Check out the setup.sql file to understand the table structure.

Usage
-----

```php
$this->load->library('acl_auth');
```

### Register a user

```php
$data = array( 'name' => 'testuser', 'password' => 'testpassword', 'extra_field' => 'value' );
$success = $this->acl_auth->register( $data );
```

### Login

```php
// Simple login
$success = $this->acl_auth->login( $user, $password );

// This logs the user in and writes user_name, user_email and user_phone into session. Also sets a cookie to remember the user.
$remember = TRUE;
$session_data = array('name', 'email', 'phone');
$success = $this->acl_auth->login( $user, $password, $remember, $session_data );
```

### Logout

```php
$success = $this->acl_auth->logout();
```

### Restrict a controller or method for users having a role

```php
class Test extends CI_Controller
{
	function __construct()
	{
		parent::__construct();

		// only allow users with 'admin' role to access all methods in this controller
		$this->acl_auth->restrict_access('admin');
	}
}
```