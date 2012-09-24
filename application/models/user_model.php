<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class User_model extends MY_Model
{
    public function has_role( $user, $role )
    {
        $this->db->join( 'user_roles ur', 'users.id = ur.users_id' );
        $this->db->join( 'roles r', 'r.id = ur.roles_id' );
        return $this->get_by( array( 'r.name' => $role, 'ur.users_id' => $user ) );
    }

    public function field_exists( $field )
    {
        return $this->db->field_exists( $field, $this->config->item('user_table', 'acl_auth') );
    }

    public function get_user( $identity )
    {
        if( ! $identity )
        {
            return false;
        }
        return $this->get_by( $this->config->item( 'identity_field', 'acl_auth' ), $identity );
    }

    public function check_token( $token )
    {
        return ( $token === $this->reset_code );
    }
}