<?php

/**
 * Copyright (c) 2010-2016 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\Mcrypt;

/**
 * Mcrypt lib class. Based on Mcrypt native php functions
 *
 * @author  Romain Cottard
 * @version 1.0.0
 */
class Mcrypt
{
    /**
     * @var integer MODE_CBC Cipher Block Chaining mode
     */
    const MODE_CBC = 1;

    /**
     * @var integer CIPHER_BLOWFISH Cipher name
     */
    const CIPHER_BLOWFISH = 1;

    /**
     * @var string $key
     */
    private $key = '';

    /**
     * @var string $mode Encryption mode.
     */
    private $mode = '';

    /**
     * @var string $cipher Encryption cipher.
     */
    private $cipher = '';

    /**
     * @var string $iv IV for encryption
     */
    private $iv = null;

    /**
     * mcrypt constructor.
     *
     * @param integer $cipher
     * @param integer $mode
     */
    public function __construct($cipher = self::CIPHER_BLOWFISH, $mode = self::MODE_CBC)
    {

        $this->setCipher($cipher);
        $this->setMode($mode);
        $this->generateIV();
    }

    /**
     * Set encryption key
     *
     * @param  string $key
     * @return $this
     * @throws \InvalidArgumentException
     */
    public function setKey($key)
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('Key cannot be empty !', 15001);
        }

        $this->key = $key;

        return $this;
    }

    /**
     * Return the IV.
     *
     * @return string
     */
    public function getIV()
    {
        return $this->iv;
    }

    /**
     * Set encryption iv
     *
     * @param  string $iv
     * @return $this
     * @throws \InvalidArgumentException
     */
    public function setIV($iv)
    {
        if (empty($iv)) {
            throw new \InvalidArgumentException('IV cannot be empty !', 15002);
        }

        $this->iv = $iv;

        return $this;
    }

    /**
     * Get Size for the IV (0: not used by the cipher/mode)
     *
     * @return integer
     */
    public function getSizeIV()
    {
        return mcrypt_get_iv_size($this->cipher, $this->mode);
    }

    /**
     * Encrypt the data string
     *
     * @param  string $data
     * @return string
     */
    public function encrypt($data)
    {
        if ($this->iv === null) {
            $dataEncrypted = mcrypt_encrypt($this->cipher, $this->key, $data, $this->mode);
        } else {
            $dataEncrypted = mcrypt_encrypt($this->cipher, $this->key, $data, $this->mode, $this->iv);
        }

        return bin2hex($dataEncrypted);
    }

    /**
     * Decrypt the data string
     *
     * @param  string $data
     * @return mixed
     * @throws \InvalidArgumentException
     */
    public function decrypt($data)
    {
        if (!is_string($data) || !preg_match('/^[0-9A-Fa-f]*$/', $data)) {
            throw new \InvalidArgumentException('blowfishDecryptCBC require hex input', 15003);
        }

        $data = pack('H*', $data);

        if ($this->iv === null) {
            $return = mcrypt_decrypt($this->cipher, $this->key, $data, $this->mode);
        } else {
            $return = mcrypt_decrypt($this->cipher, $this->key, $data, $this->mode, $this->iv);
        }

        return rtrim($return, "\0");//str_replace(chr(0), '', $return);
    }

    /**
     * Set cipher
     *
     * @param  integer $cipher
     * @return $this
     * @throws \DomainException
     */
    protected function setCipher($cipher)
    {
        switch ($cipher) {
            case static::CIPHER_BLOWFISH:
                $this->cipher = MCRYPT_BLOWFISH;
                break;
            default:
                throw new \DomainException('Unsupported cipher method !', 15004);
        }

        return $this;
    }

    /**
     * Set mode
     *
     * @param  integer $mode
     * @return $this
     * @throws \DomainException
     */
    protected function setMode($mode)
    {
        switch ($mode) {
            case static::MODE_CBC:
                $this->mode = MCRYPT_MODE_CBC;
                break;
            default:
                throw new \DomainException('Unsupported encryption method !', 15005);
        }

        return $this;
    }

    /**
     * Generate random IV & set it as property
     *
     * @return $this
     */
    protected function generateIV()
    {
        $sizeIV = $this->getSizeIV();

        if ($sizeIV === 0) {
            return $this;
        }

        $this->setIV(mcrypt_create_iv($sizeIV, MCRYPT_RAND));

        return $this;
    }
}
