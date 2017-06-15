<?php

/*
 * This file is part of SwiftMailer.
 * (c) 2004-2009 Chris Corbyn
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Handles LOGIN authentication.
 *
 * @author Chris Corbyn
 */
class Swift_Transport_Esmtp_Auth_LoginAuthenticator implements Swift_Transport_Esmtp_Authenticator
{
    /**
     * {@inheritdoc}
     */
    public function getAuthKeyword(): string
    {
        return 'LOGIN';
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(Swift_Transport_SmtpAgent $agent, string $username, string $password): bool
    {
        try {
            $agent->executeCommand("AUTH LOGIN\r\n", array(334));
            $agent->executeCommand(sprintf("%s\r\n", base64_encode($username)), array(334));
            $agent->executeCommand(sprintf("%s\r\n", base64_encode($password)), array(235));

            return true;
        } catch (Swift_TransportException $e) {
            $agent->executeCommand("RSET\r\n", array(250));

            return false;
        }
    }
}
