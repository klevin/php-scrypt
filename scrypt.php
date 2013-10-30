<?php
/**
 * This file contains an example helper classes for the php-scrypt extension.
 *
 * As with all cryptographic code; it is recommended that you use a tried and
 * tested library which uses this library; rather than rolling your own.
 *
 * PHP version 5
 *
 * @category Security
 * @package  Scrypt
 * @author   Dominic Black <thephenix@gmail.com>
 * @license  http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link     http://github.com/DomBlack/php-scrypt
 */

/**
 * This class abstracts away from scrypt module, allowing for easy use.
 *
 * You can create a new hash for a password by calling Password::hash($password)
 *
 * You can check a password by calling Password::check($password, $hash)
 *
 * @category Security
 * @package  Scrypt
 * @author   Dominic Black <thephenix@gmail.com>
 * @license  http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link     http://github.com/DomBlack/php-scrypt
 */
class Password
{
    /**
     * @var int The key length
     */
    private static $_keyLength = 33;

    /**
     * Generates a random salt
     *
     * @param int $length The length of the salt
     *
     * @return string The salt
     */
    public static function generateSalt($length = 18)
    {
        // Let's generate a string of random bytes to use as a salt
        // First, try openssl's CSPRNG
        if(function_exists('openssl_random_pseudo_bytes')) {
          try {
            $rand = openssl_random_pseudo_bytes($length);
            if(strlen($rand) == $length) {
              return $rand; // It returned a string as long as expected
            }
          } catch(Exception $ex) {
            // I'm not 100% sure what to put here, but it will just continue down the line
            // and try mcrypt_create_iv() next anyway.
            trigger_error("openssl_random_pseudo_bytes() triggered an exception in scrypt.php", E_USER_WARNING);
          }
        }
        // Using PHP < 5.3.0? Okay, try using mcrypt to do the same thing
        if(function_exists('mcrypt_create_iv')) {
          try {
            $rand = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if(strlen($rand) == $length) {
              return $rand; // It returned as tring as long as expected
            }
          } catch(Exception $ex) {
            trigger_error("mcrypt_create_iv() triggered an exception in scrypt.php", E_USER_WARNING);
          }
        }
        // If we are on a Linux/BSD operating system, /dev/urandom should provide adequate entropy
        if(is_readable('/dev/urandom')) {
          try {
            // Open the non-blocking random device
            $fp = fopen('/dev/urandom', 'r');
            // Read $length bytes from the device
            $rand = fread($fp, $length);
            // Close the file handler for the device
            fclose($fp);
            if(strlen($rand) == $length) {
              return $rand;
            }
          } catch(Exception $ex) {
            trigger_error("Error with reading bytes from /dev/urandom in scrypt.php", E_USER_WARNING);
          }
        }
        /*
        // WINDOWS ONLY: Access Microsoft's Crypto API for random bytes
        if (@class_exists('COM')) {
          try {
            $CAPI_Util = new COM('CAPICOM.Utilities.1');
            $rand = $CAPI_Util->GetRandom($length,0);
            return $rand;
          } catch (Exception $ex) {
            trigger_error("COM Failed. You should probably look at the code since it wasn't adequately ".
                          "tested for Windows platforms.", E_USER_WARNING);
          }
        }*/
        // If we're still here, I /guess/ we can just use mt_rand, if you insist.
        trigger_error("No suitable random number generator found, falling back to a weak one.", E_USER_NOTICE);
        $rand = '';
        for($i = 0; $i < $length; ++$i) {
          $rand .= chr(mt_rand(0,255));
        }
        return $rand;
    }

    /**
     * Create a password hash
     *
     * @param string $password The clear text password
     * @param string $salt     The salt to use, or null to generate a random one
     * @param int    $N        The CPU difficultly (must be a power of 2,  > 1)
     * @param int    $r        The memory difficultly
     * @param int    $p        The parallel difficultly
     *
     * @return string The hashed password
     */
    public static function hash($password, $salt = false, $N = 16384, $r = 8, $p = 1)
    {
        if ($salt === false) {
            $salt = self::generateSalt();
        }

        $hash = base64_encode(hex2bin(scrypt($password, $salt, $N, $r, $p, self::$_keyLength)));

        return $N.'$'.$r.'$'.$p.'$'. base64_encode($salt).'$'.$hash;
    }

    /**
     * Check a clear text password against a hash
     *
     * @param string $password The clear text password
     * @param string $hash     The hashed password
     *
     * @return boolean If the clear text matches
     */
    public static function check($password, $hash)
    {
        // Is there actually a hash?
        if (!strlen($hash)) {
            return false;
        }

        list($N, $r, $p, $salt, $hash) = explode('$', $hash);

        // No empty fields?
        if (empty($N) or empty($r) or empty($p) or empty($salt) or empty($hash)) {
            return false;
        }

        // Are numeric values numeric?
        if (!is_numeric($N) or !is_numeric($r) or !is_numeric($p)) {
            return false;
        }

        $calculated = base64_encode(hex2bin(scrypt($password, base64_decode($salt), $N, $r, $p, self::$_keyLength)));

        // Use compareStrings to avoid timeing attacks
        return self::compareStrings($hash, $calculated);
    }

    /**
     * Zend Framework (http://framework.zend.com/)
     *
     * @link      http://github.com/zendframework/zf2 for the canonical source repository
     * @copyright Copyright (c) 2005-2013 Zend Technologies USA Inc. (http://www.zend.com)
     * @license   http://framework.zend.com/license/new-bsd New BSD License
     *
     *
     * Compare two strings to avoid timing attacks
     *
     * C function memcmp() internally used by PHP, exits as soon as a difference
     * is found in the two buffers. That makes possible of leaking
     * timing information useful to an attacker attempting to iteratively guess
     * the unknown string (e.g. password).
     *
     * @param  string $expected
     * @param  string $actual
     *
     * @return boolean If the two strings match.
     */
    public static function compareStrings($expected, $actual)
    {
        $expected     = (string) $expected;
        $actual       = (string) $actual;
        $lenExpected  = strlen($expected);
        $lenActual    = strlen($actual);
        $len          = min($lenExpected, $lenActual);

        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($expected[$i]) ^ ord($actual[$i]);
        }
        $result |= $lenExpected ^ $lenActual;

        return ($result === 0);
    }
}
// Using an old version of PHP? never fear bin2hex() is here :)
if(!function_exists('bin2hex')) {
    function hex2bin($str) {
        if(strlen($str) % 2 === 0) {
          return pack('H*', $str);
        }
        trigger_error("The length of the input string for bin2hex() must be an even number.");
        return false;
    }
}
