<?php

declare(strict_types=1);

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

class Token
{
    /**
     * Decode a JWT token
     *
     * @param string|null $token
     * @param string $publicKey
     * @param int $leeway
     * @param string $algorithm
     * @return stdClass|null
     */
    public static function decode(?string $token = null, string $publicKey, int $leeway = 0, string $algorithm = 'RS256'): ?stdClass
    {
        JWT::$leeway = $leeway;
        $publicKey = self::buildPublicKey($publicKey);

        return $token ? JWT::decode($token, new Key($publicKey, $algorithm)) : null;
    }

    /**
     * Build a valid public key from a string
     *
     * @param  string  $key
     * @return string
     */
    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($key, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }

    /**
     * Get the plain public key from a string
     *
     * @param  string  $key
     * @return string
     */
    public static function plainPublicKey(string $key): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
        $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));

        return str_replace('\n', '', $string);
    }
}
