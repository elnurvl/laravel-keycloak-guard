<?php

declare(strict_types=1);

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use stdClass;

class Token
{
    /**
     * Decode a JWT token
     *
     * @param string $token
     * @param int $leeway
     *
     * @return stdClass|null
     */
    public static function decode(string $token, int $leeway = 0): ?stdClass
    {
        list(, $payload, ) = explode('.', $token);
        $payload = json_decode(base64_decode($payload));
        $iss = $payload->iss;
        $publicKey = PublicKey::getPublicKey($iss);

        JWT::$leeway = $leeway;

        return $token ? JWT::decode($token, $publicKey) : null;
    }
}
