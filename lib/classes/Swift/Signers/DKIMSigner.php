<?php

/*
 * This file is part of SwiftMailer.
 * (c) 2004-2009 Chris Corbyn
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * DKIM Signer used to apply DKIM Signature to a message.
 * DKIM is the further development of DomainKey. This class obsoletes DomainKeySigner.php.
 * This class follows RFC6376.
 *
 * @author Xavier De Cock <xdecock@gmail.com>
 * @author Ludwig Grill (www.rotzbua.de)
 */
class Swift_Signers_DKIMSigner implements Swift_Signers_HeaderSigner
{
    /**
     * PrivateKey.
     *
     * @var string
     */
    protected $privateKey;

    /**
     * DomainName.
     *
     * @var string
     */
    protected $domainName;

    /**
     * Selector.
     *
     * @var string
     */
    protected $selector;

    private $passphrase = '';

    /**
     * Hash algorithm used.
     *
     * @see RFC6376 3.3: Signers MUST implement and SHOULD sign using rsa-sha256.
     *
     * @var string
     */
    protected $hashAlgorithm = 'rsa-sha256';

    /**
     * Contains openssl representation of $_hashAlgorithm.
     * Is only set by setHashAlgorithm().
     *
     * @var int
     */
    protected $hashAlgorithmOpenssl = -1;

    /**
     * Body canon method.
     *
     * @var string
     */
    protected $bodyCanon = 'simple';

    /**
     * Header canon method.
     *
     * @var string
     */
    protected $headerCanon = 'simple';

    /**
     * Headers not being signed.
     *
     * @see RFC6376 - 5.4.1. Recommended Signature Content
     *
     * @var array
     */
    protected $ignoredHeaders = array('return-path'            => true, // RFC6376
                                      'received'               => true, // RFC6376
                                      'comments'               => true, // RFC6376
                                      'keywords'               => true, // RFC6376
                                      'authentication-results' => true, // good practice recommendation
    );

    /**
     * Signer identity.
     *
     * @var string
     */
    protected $signerIdentity;

    /**
     * BodyLength.
     *
     * @var int
     */
    protected $bodyLen = 0;

    /**
     * Maximum signedLen.
     *
     * @var int
     */
    protected $maxLen = PHP_INT_MAX;

    /**
     * Embedded bodyLen in signature.
     *
     * @var bool
     */
    protected $showLen = false;

    /**
     * When the signature has been applied.
     * If integer is set, value is used.
     * If false means no timestamp is embedded.
     *
     * @var bool|int
     */
    protected $signatureTimestamp = true;

    /**
     * When the signature will expires.
     * If integer is set, value is used.
     * If false means no timestamp embedded.
     *
     * @var bool|int
     */
    protected $signatureExpiration = false;

    /**
     * Must we embed signed headers?
     *
     * @var bool
     */
    protected $debugHeaders = false;

    // work variables
    /**
     * Headers used to generate hash.
     *
     * @var array
     */
    protected $signedHeaders = array();

    /**
     * If debugHeaders is set store debugData here.
     *
     * @var string
     */
    private $debugHeadersData = '';

    /**
     * Stores the bodyHash.
     *
     * @var string
     */
    private $bodyHash = '';

    /**
     * Stores the signature header.
     *
     * @var Swift_Mime_Headers_ParameterizedHeader
     */
    protected $dkimHeader;

    /**
     * Query methods used to retrieve the public key by validator.
     *
     * @var string false if not used
     */
    private $pkeyRequestMethod = '';

    private $bodyHashHandler;

    private $headerHash;

    private $headerCanonData = '';

    private $bodyCanonEmptyCounter = 0;

    private $bodyCanonIgnoreStart = 2;

    private $bodyCanonSpace = false;

    private $bodyCanonLastChar = '';

    private $bodyCanonLine = '';

    private $bound = array();

    /**
     * Constructor.
     *
     * @param string $privateKey RSA: >=1024bit
     * @param string $domainName
     * @param string $selector
     * @param string $passphrase
     */
    public function __construct(string $privateKey, string $domainName, string $selector, string $passphrase = '')
    {
        $this->privateKey = $privateKey;
        $this->domainName = $domainName;
        $this->signerIdentity = '@'.$domainName;
        $this->selector = $selector;
        $this->passphrase = $passphrase;
    }

    /**
     * Reset the Signer.
     *
     * @see Swift_Signer::reset()
     */
    public function reset()
    {
        $this->headerHash = null;
        $this->signedHeaders = array();
        $this->bodyHash = null;
        $this->bodyHashHandler = null;
        $this->bodyCanonIgnoreStart = 2;
        $this->bodyCanonEmptyCounter = 0;
        $this->bodyCanonLastChar = null;
        $this->bodyCanonSpace = false;
    }

    /**
     * Writes $bytes to the end of the stream.
     *
     * Writing may not happen immediately if the stream chooses to buffer.  If
     * you want to write these bytes with immediate effect, call {@link commit()}
     * after calling write().
     *
     * This method returns the sequence ID of the write (i.e. 1 for first, 2 for
     * second, etc etc).
     *
     * @param string $bytes
     *
     * @throws Swift_IoException
     */
    public function write($bytes)
    {
        $this->canonicalizeBody($bytes);
        foreach ($this->bound as $is) {
            $is->write($bytes);
        }
    }

    /**
     * For any bytes that are currently buffered inside the stream, force them
     * off the buffer.
     */
    public function commit()
    {
        // Nothing to do
    }

    /**
     * Attach $is to this stream.
     * The stream acts as an observer, receiving all data that is written.
     * All {@link write()} and {@link flushBuffers()} operations will be mirrored.
     *
     * @param Swift_InputByteStream $is
     */
    public function bind(Swift_InputByteStream $is)
    {
        // Don't have to mirror anything
        $this->bound[] = $is;
    }

    /**
     * Remove an already bound stream.
     * If $is is not bound, no errors will be raised.
     * If the stream currently has any buffered data it will be written to $is
     * before unbinding occurs.
     *
     * @param Swift_InputByteStream $is
     */
    public function unbind(Swift_InputByteStream $is)
    {
        // Don't have to mirror anything
        foreach ($this->bound as $k => $stream) {
            if ($stream === $is) {
                unset($this->bound[$k]);

                return;
            }
        }
    }

    /**
     * Flush the contents of the stream (empty it) and set the internal pointer
     * to the beginning.
     *
     * @throws Swift_IoException
     */
    public function flushBuffers()
    {
        $this->reset();
    }

    /**
     * Set and initialise hash algorithm, must be one of 'rsa-sha1' or 'rsa-sha256'.
     *
     * @param string $hash 'rsa-sha1' or 'rsa-sha256'
     *
     * @throws Swift_SwiftException
     *
     * @return $this
     */
    public function setHashAlgorithm(string $hash)
    {
        switch ($hash) {
            case 'rsa-sha1':
                $this->hashAlgorithm = 'rsa-sha1';
                $this->bodyHashHandler = hash_init('sha1');
                $this->hashAlgorithmOpenssl = OPENSSL_ALGO_SHA1;
                break;
            case 'rsa-sha256':
                if (!defined('OPENSSL_ALGO_SHA256')) {
                    // should be only thrown by php versions below 5.4.8
                    throw new Swift_SwiftException('Unable to set sha256 as it is not supported by OpenSSL.');
                }
                $this->hashAlgorithm = 'rsa-sha256';
                $this->bodyHashHandler = hash_init('sha256');
                $this->hashAlgorithmOpenssl = OPENSSL_ALGO_SHA256;
                break;
            default:
                throw new Swift_SwiftException('Unable to set the hash algorithm, must be one of rsa-sha1 or rsa-sha256 ('.$hash.' given).');
        }

        return $this;
    }

    /**
     * Set the body canonicalization algorithm.
     *
     * @param string $canon
     *
     * @throws Swift_SwiftException
     *
     * @return $this
     */
    public function setBodyCanon($canon)
    {
        switch ($canon) {
            case 'simple':
                $this->bodyCanon = 'simple';
                break;
            case 'relaxed':
                $this->bodyCanon = 'relaxed';
                break;
            default:
                throw new Swift_SwiftException('Unable to set the body canon, must be one of simple or relaxed ('.$canon.' given).');
        }

        return $this;
    }

    /**
     * Set the header canonicalization algorithm.
     *
     * @param string $canon
     *
     * @throws Swift_SwiftException
     *
     * @return $this
     */
    public function setHeaderCanon(string $canon)
    {
        switch ($canon) {
            case 'simple':
                $this->headerCanon = 'simple';
                break;
            case 'relaxed':
                $this->headerCanon = 'relaxed';
                break;
            default:
                throw new Swift_SwiftException('Unable to set the header canon, must be one of simple or relaxed ('.$canon.' given).');
        }

        return $this;
    }

    /**
     * Set the signer identity.
     *
     * @param string $identity
     *
     * @return $this
     */
    public function setSignerIdentity(string $identity)
    {
        $this->signerIdentity = $identity;

        return $this;
    }

    /**
     * Set the length of the body to sign.
     *
     * @param bool|int $len
     *
     * @return $this
     */
    public function setBodySignedLen($len)
    {
        if ($len === true) {
            $this->showLen = true;
            $this->maxLen = PHP_INT_MAX;
        } elseif ($len === false) {
            $this->showLen = false;
            $this->maxLen = PHP_INT_MAX;
        } else {
            $this->showLen = true;
            $this->maxLen = (int) $len;
        }

        return $this;
    }

    /**
     * Set the signature timestamp.
     * If true actual time is used.
     * If false no timestamp will be set.
     * Timestamp in the future are not recommended.
     *
     * @param bool|int $time De-/Activate|A timestamp
     *
     * @throws Swift_SwiftException
     *
     * @return $this
     */
    public function setSignatureTimestamp($time)
    {
        if (!(is_bool($time) || (is_int($time) && 0 < $time))) {
            throw new Swift_SwiftException('Unable to set the signature timestamp ('.$time.' given).');
        }
        if (!(is_bool($time) || $this->signatureExpiration === false || ($this->signatureExpiration !== false && $time < $this->signatureExpiration))) {
            throw new Swift_SwiftException('Signature timestamp must be less than expiration timestamp.');
        }
        $this->signatureTimestamp = $time;

        return $this;
    }

    /**
     * Set the signature expiration timestamp.
     * If true actual time + delta is used.
     * If false no timestamp will be set.
     *
     * @param bool|int $time De-/Activate|A timestamp
     *
     * @throws Swift_SwiftException
     *
     * @return $this
     */
    public function setSignatureExpiration($time)
    {
        if ($time === true) {
            $time = time() + 60 * 60 * 24 * 30; // dkim signature for 30 days valid
        }
        if (!(is_bool($time) || (is_int($time) && 0 < $time))) {
            throw new Swift_SwiftException('Unable to set the expiration timestamp ('.$time.' given).');
        }
        if (!(is_bool($time) || $this->signatureTimestamp === false || ($this->signatureTimestamp !== false && $this->signatureTimestamp < $time))) {
            throw new Swift_SwiftException('Expiration timestamp must be grater than signature timestamp.');
        }
        $this->signatureExpiration = $time;

        return $this;
    }

    /**
     * Set query methods used to retrieve the public key, actually only one method defined.
     *
     * @param $method string false or 'dns/txt'
     *
     * @throws Swift_SwiftException
     *
     * @return Swift_Signers_DKIMSigner
     */
    public function setPKeyQueryMethod(string $method)
    {
        if (!($method === '' || $method === 'dns/txt')) {
            throw new Swift_SwiftException('Unable to set query method ('.$method.' given).');
        }

        $this->pkeyRequestMethod = $method;

        return $this;
    }

    /**
     * Enable / disable the DebugHeaders.
     *
     * @param bool $debug
     *
     * @return Swift_Signers_DKIMSigner
     */
    public function setDebugHeaders(bool $debug)
    {
        $this->debugHeaders = $debug;

        return $this;
    }
    
    /**
     * Start Body.
     * @throws \Swift_SwiftException
     * @return Swift_Signers_DKIMSigner
     */
    public function startBody()
    {
        // Init hash algorithm
        $this->setHashAlgorithm($this->hashAlgorithm);
        $this->bodyCanonLine = '';
        
        return $this;
    }

    /**
     * End Body.
     * 
     * @return Swift_Signers_DKIMSigner
     */
    public function endBody()
    {
        $this->endOfBody();
        
        return $this;
    }

    /**
     * Returns the list of Headers Tampered by this plugin.
     *
     * @return array
     */
    public function getAlteredHeaders(): array
    {
        if ($this->debugHeaders) {
            return array('DKIM-Signature', 'X-DebugHash');
        }
    
        return array('DKIM-Signature');
    }

    /**
     * Adds an ignored Header.
     *
     * @param string $header_name
     *
     * @return Swift_Signers_DKIMSigner
     */
    public function ignoreHeader(string $header_name)
    {
        $this->ignoredHeaders[strtolower($header_name)] = true;

        return $this;
    }

    /**
     * Set the headers to sign.
     *
     * @param Swift_Mime_SimpleHeaderSet $headers
     *
     * @return Swift_Signers_DKIMSigner
     */
    public function setHeaders(Swift_Mime_SimpleHeaderSet $headers)
    {
        $this->headerCanonData = '';
        // Loop through Headers
        $listHeaders = $headers->listAll();
        foreach ($listHeaders as $hName) {
            // Check if we need to ignore Header
            if (!isset($this->ignoredHeaders[strtolower($hName)])) {
                if ($headers->has($hName)) {
                    $tmp = $headers->getAll($hName);
                    foreach ($tmp as $header) {
                        if ($header->getFieldBody() !== '') {
                            $this->addHeader($header->toString());
                            $this->signedHeaders[] = $header->getFieldName();
                        }
                    }
                }
            }
        }

        return $this;
    }

    /**
     * Add the signature to the given Headers.
     *
     * @param Swift_Mime_SimpleHeaderSet $headers
     *
     * @throws Swift_SwiftException
     *
     * @return Swift_Signers_DKIMSigner
     */
    public function addSignature(Swift_Mime_SimpleHeaderSet $headers)
    {
        // Prepare the DKIM-Signature
        $params = array('v' => '1', // required
                        'a' => $this->hashAlgorithm, // required
                        'bh' => base64_encode($this->bodyHash), // required
                        'd' => $this->domainName, // required
                        'h' => implode(':', $this->signedHeaders), // required
                        'i' => $this->signerIdentity, // optional
                        's' => $this->selector, // required
        );
        // optional, 'simple' is default, only if canon is different add parameter
        if ($this->bodyCanon !== 'simple') {
            $params['c'] = $this->headerCanon.'/'.$this->bodyCanon;
        } elseif ($this->headerCanon !== 'simple') {
            $params['c'] = $this->headerCanon;
        }
        // optional
        if ($this->showLen) {
            $params['l'] = $this->bodyLen;
        }
        // optional
        if ($this->pkeyRequestMethod !== '') {
            $params['q'] = $this->pkeyRequestMethod;
        }
        // optional
        if ($this->signatureTimestamp !== false) {
            if ($this->signatureTimestamp === true) {
                $params['t'] = time(); // actual time
            } else {
                $params['t'] = $this->signatureTimestamp;
            }
        }
        // optional
        if ($this->signatureExpiration !== false) {
            if ($this->signatureExpiration === true) {
                $params['x'] = time() + 60 * 60 * 24 * 30; // dkim signature for 30 days valid
            } else {
                $params['x'] = $this->signatureExpiration;
            }
        }
        // check timestamps, expiration must be after signing
        if (isset($params['t'], $params['x']) && $params['t'] < $params['x']) {
            throw new Swift_SwiftException('Expiration timestamp must be higher than signature timestamp');
        }
        // optional
        if ($this->debugHeaders) {
            $params['z'] = implode('|', $this->debugHeadersData);
        }

        // concat signature
        $string = '';
        foreach ($params as $k => $v) {
            $string .= $k.'='.$v.'; ';
        }
        $string = trim($string);
        $headers->addTextHeader('DKIM-Signature', $string);
        // Add the last DKIM-Signature
        $tmp = $headers->getAll('DKIM-Signature');
        $this->dkimHeader = end($tmp);
        $this->addHeader(trim($this->dkimHeader->toString())."\r\n b=", true);
        if ($this->debugHeaders) {
            $headers->addTextHeader('X-DebugHash', base64_encode($this->headerHash));
        }
        $this->dkimHeader->setValue($string.' b='.trim(chunk_split(base64_encode($this->getEncryptedHash()), 73, ' ')));

        return $this;
    }

    /* Private helpers */

    protected function addHeader(string $header, bool $is_sig = false)
    {
        switch ($this->headerCanon) {
            case 'simple':
                // Nothing to do
                break;
            case 'relaxed':
                // Prepare Header and cascade
                $exploded = explode(':', $header, 2);
                $name = strtolower(trim($exploded[0]));
                $value = str_replace("\r\n", '', $exploded[1]);
                $value = preg_replace("/[ \t][ \t]+/", ' ', $value);
                $header = $name.':'.trim($value).($is_sig ? '' : "\r\n");
                break;
        }
        $this->addToHeaderHash($header);
    }

    protected function canonicalizeBody(string $string)
    {
        $len = strlen($string);
        $canon = '';
        $method = ($this->bodyCanon === 'relaxed');
        for ($i = 0; $i < $len; ++$i) {
            if ($this->bodyCanonIgnoreStart > 0) {
                --$this->bodyCanonIgnoreStart;
                continue;
            }
            switch ($string[$i]) {
                case "\r":
                    $this->bodyCanonLastChar = "\r";
                    break;
                case "\n":
                    if ($this->bodyCanonLastChar === "\r") {
                        if ($method) {
                            $this->bodyCanonSpace = false;
                        }
                        if ($this->bodyCanonLine === '') {
                            ++$this->bodyCanonEmptyCounter;
                        } else {
                            $this->bodyCanonLine = '';
                            $canon .= "\r\n";
                        }
                    } else {
                        // Wooops Error
                        // todo handle it but should never happen
                        // todo what is this error?
                        throw new Swift_SwiftException('Error while canonicalizing Body');
                    }
                    break;
                case ' ':
                case "\t":
                    if ($method) {
                        $this->bodyCanonSpace = true;
                        break;
                    }
                default:
                    if ($this->bodyCanonEmptyCounter > 0) {
                        $canon .= str_repeat("\r\n", $this->bodyCanonEmptyCounter);
                        $this->bodyCanonEmptyCounter = 0;
                    }
                    if ($this->bodyCanonSpace) {
                        $this->bodyCanonLine .= ' ';
                        $canon .= ' ';
                        $this->bodyCanonSpace = false;
                    }
                    $this->bodyCanonLine .= $string[$i];
                    $canon .= $string[$i];
            }
        }
        $this->addToBodyHash($canon);
    }

    protected function endOfBody()
    {
        // Add trailing Line return if last line is non empty
        if (strlen($this->bodyCanonLine) > 0) {
            $this->addToBodyHash("\r\n");
        }
        // TODO add a test for this case
        // If body empty it still contains a CRLF in "simple" mode
        // RFC6376 - 3.4.3. The "simple" Body Canonicalization Algorithm
        if ($this->bodyLen === 0 && $this->bodyCanon === 'simple') {
            $this->addToBodyHash("\r\n");
        }
        $this->bodyHash = hash_final($this->bodyHashHandler, true);
    }

    private function addToBodyHash(string $string)
    {
        $len = strlen($string);
        if ($len > ($new_len = ($this->maxLen - $this->bodyLen))) {
            $string = substr($string, 0, $new_len);
            $len = $new_len;
        }
        hash_update($this->bodyHashHandler, $string);
        $this->bodyLen += $len;
    }

    private function addToHeaderHash(string $header)
    {
        if ($this->debugHeaders) {
            $this->debugHeadersData[] = trim($header);
        }
        $this->headerCanonData .= $header;
    }

    /**
     * @throws Swift_SwiftException
     *
     * @return string
     */
    private function getEncryptedHash(): string
    {
        $signature = '';
        
        $pkeyId = openssl_get_privatekey($this->privateKey, $this->passphrase);
        if (!$pkeyId) {
            throw new Swift_SwiftException('Unable to load DKIM Private Key ['.openssl_error_string().']');
        }
        // get details about key
        $pkeyId_details = openssl_pkey_get_details($pkeyId);
        // Security: dkim headers below 1024 bit will be ignored by google mail
        // RFC6376 3.3.3. Key Sizes: The security constraint that keys smaller than 1024 bits are subject to off-line attacks
        // Vulnerability Note VU#268267 https://www.kb.cert.org/vuls/id/268267
        if (isset($pkeyId_details['type'], $pkeyId_details['bits']) && $pkeyId_details['type'] === OPENSSL_KEYTYPE_RSA && $pkeyId_details['bits'] < 1024) {
            throw new  Swift_SwiftException('DKIM Private Key must have at least 1024 bit or higher. See VU#268267 https://www.kb.cert.org/vuls/id/268267');
        }
        // create signature
        if (!openssl_sign($this->headerCanonData, $signature, $pkeyId, $this->hashAlgorithmOpenssl)) {
            throw new Swift_SwiftException('Unable to sign DKIM Hash ['.openssl_error_string().']');
        }

        return $signature;
    }
}
