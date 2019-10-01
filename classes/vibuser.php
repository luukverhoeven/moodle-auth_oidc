<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 *
 *
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 *
 * @package   moodle-auth_oidc
 * @copyright 01/10/2019 Mfreak.nl | LdesignMedia.nl - Luuk Verhoeven
 * @author    Luuk Verhoeven
 **/

namespace auth_oidc;

use moodle_exception;

defined('MOODLE_INTERNAL') || die;

/**
 * Class vibuser
 *
 * @package auth_oidc
 */
final class vibuser {

    /**
     * @var int
     */
    private $userid;

    /**
     * vibuser constructor.
     *
     * @param int $userid
     */
    public function __construct(int $userid) {
        $this->userid = $userid;
    }

    /**
     * get_webservice_access_token
     *
     * @return bool|string
     * @throws \dml_exception
     * @throws moodle_exception
     */
    protected function get_webservice_access_token() {
        $httpclient = new httpclient();
        $response = $httpclient->post('https://services.vib.be/connect/token', [
            'client_secret' => get_config('auth_oidc', 'clientsecret'),
            'client_id' => get_config('auth_oidc', 'clientid'),
            'grant_type' => 'client_credentials',
            'scope' => 'users',
        ]);

        if ($httpclient->info['http_code'] !== 200) {
            throw new moodle_exception('Could not get token');
        }

        $r = json_decode($response);

        if (is_null($r)) {
            throw new moodle_exception("Could not decode JSON token response");
        }

        if (!isset($r->access_token)) {
            return false;
        }

        return $r->access_token;

    }

    /**
     * @param string $username
     *
     * @return bool
     * @throws moodle_exception
     */
    protected function get_webservice_user(string $username) {

        if (!is_numeric($username)) {
            return false;
        }

        $token = $this->get_webservice_access_token();

        if (empty($token)) {
            return false;
        }

        $httpclient = new httpclient();
        $httpclient->setHeader(['Content-Type: application/json', "Authorization: Bearer " . $token]);
        $response = $httpclient->get('https://services.vib.be/api/v1/users/' . $username);

        if ($httpclient->info['http_code'] !== 200) {
            throw new moodle_exception('Could not get user details');
        }

        $r = json_decode($response);

        if (is_null($r)) {
            throw new moodle_exception("Could not decode JSON token response");
        }

        if(!isset($r->FirstName)){
            return false;
        }

        return $r;
    }

    /**
     * @return bool
     * @throws \dml_exception
     * @throws moodle_exception
     */
    public function update_user_details() {
        global $USER;
        $user = \core_user::get_user($this->userid, '*', MUST_EXIST);
        $vibuser = $this->get_webservice_user($user->username);

        if (empty($vibuser)) {
            return false;
        }

        unset($user->password);

        $user->firstname = $vibuser->FirstName;
        $user->lastname = $vibuser->LastName;
        $user->email = $vibuser->Email;
        $user->phone1 = $vibuser->Phone;

        user_update_user($user);

        $USER = $user;

        return true;
    }

}