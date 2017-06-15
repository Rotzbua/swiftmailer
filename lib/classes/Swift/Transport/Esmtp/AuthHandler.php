<?php

/*
 * This file is part of SwiftMailer.
 * (c) 2004-2009 Chris Corbyn
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * An ESMTP handler for AUTH support.
 *
 * @author Chris Corbyn
 */
class Swift_Transport_Esmtp_AuthHandler implements Swift_Transport_EsmtpHandler
{
    /**
     * Authenticators available to process the request.
     *
     * @var Swift_Transport_Esmtp_Authenticator[]
     */
    private $authenticators = array();

    /**
     * The username for authentication.
     *
     * @var string
     */
    private $username;

    /**
     * The password for authentication.
     *
     * @var string
     */
    private $password;

    /**
     * The auth mode for authentication.
     *
     * @var string
     */
    private $auth_mode;

    /**
     * The ESMTP AUTH parameters available.
     *
     * @var string[]
     */
    private $esmtpParams = array();

    /**
     * Create a new AuthHandler with $authenticators for support.
     *
     * @param Swift_Transport_Esmtp_Authenticator[] $authenticators
     */
    public function __construct(array $authenticators)
    {
        $this->setAuthenticators($authenticators);
    }

    /**
     * Set the Authenticators which can process a login request.
     *
     * @param Swift_Transport_Esmtp_Authenticator[] $authenticators
     */
    public function setAuthenticators(array $authenticators)
    {
        $this->authenticators = $authenticators;
    }

    /**
     * Get the Authenticators which can process a login request.
     *
     * @return Swift_Transport_Esmtp_Authenticator[]
     */
    public function getAuthenticators(): array
    {
        return $this->authenticators;
    }

    /**
     * Set the username to authenticate with.
     *
     * @param string $username
     */
    public function setUsername($username)
    {
        $this->username = $username;
    }

    /**
     * Get the username to authenticate with.
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Set the password to authenticate with.
     *
     * @param string $password
     */
    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Get the password to authenticate with.
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Set the auth mode to use to authenticate.
     *
     * @param string $mode
     */
    public function setAuthMode($mode)
    {
        $this->auth_mode = $mode;
    }

    /**
     * Get the auth mode to use to authenticate.
     *
     * @return string
     */
    public function getAuthMode(): string
    {
        return $this->auth_mode;
    }

    /**
     * {@inheritdoc}
     */
    public function getHandledKeyword(): string
    {
        return 'AUTH';
    }

    /**
     * {@inheritdoc}
     */
    public function setKeywordParams(array $parameters)
    {
        $this->esmtpParams = $parameters;
    }

    /**
     * Runs immediately after a EHLO has been issued.
     *
     * @param Swift_Transport_SmtpAgent $agent to read/write
     * @throws \Swift_TransportException
     */
    public function afterEhlo(Swift_Transport_SmtpAgent $agent)
    {
        if ($this->username) {
            $count = 0;
            foreach ($this->getAuthenticatorsForAgent($agent) as $authenticator) {
                if (in_array(strtolower($authenticator->getAuthKeyword()),
                    array_map('strtolower', $this->esmtpParams))) {
                    ++$count;
                    if ($authenticator->authenticate($agent, $this->username, $this->password)) {
                        return;
                    }
                }
            }
            throw new Swift_TransportException(
                'Failed to authenticate on SMTP server with username "'.
                $this->username.'" using '.$count.' possible authenticators'
                );
        }
    }

    /**
     * Not used.
     */
    public function getMailParams(): array
    {
        return array();
    }

    /**
     * Not used.
     */
    public function getRcptParams(): array
    {
        return array();
    }

    /**
     * Not used.
     */
    public function onCommand(Swift_Transport_SmtpAgent $agent, $command, $codes = array(), &$failedRecipients = null, &$stop = false)
    {
    }

    /**
     * Returns +1, -1 or 0 according to the rules for usort().
     *
     * This method is called to ensure extensions can be execute in an appropriate order.
     *
     * @param string $esmtpKeyword to compare with
     *
     * @return int
     */
    public function getPriorityOver(string $esmtpKeyword): int
    {
        return 0;
    }

    /**
     * {@inheritdoc}
     */
    public function exposeMixinMethods(): array
    {
        return array('setUsername', 'getUsername', 'setPassword', 'getPassword', 'setAuthMode', 'getAuthMode');
    }

    /**
     * Not used.
     */
    public function resetState()
    {
    }

    /**
     * Returns the authenticator list for the given agent.
     *
     * @param Swift_Transport_SmtpAgent $agent
     *
     * @return array
     * @throws \Swift_TransportException
     */
    protected function getAuthenticatorsForAgent(Swift_Transport_SmtpAgent $agent): array
    {
        if (!$mode = strtolower($this->auth_mode)) {
            return $this->authenticators;
        }

        foreach ($this->authenticators as $authenticator) {
            if (strtolower($authenticator->getAuthKeyword()) === $mode) {
                return array($authenticator);
            }
        }

        throw new Swift_TransportException('Auth mode '.$mode.' is invalid');
    }
}
