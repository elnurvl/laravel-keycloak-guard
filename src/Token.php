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
     * @param string|null $token
     * @param int $leeway
     *
     * @return stdClass|null
     */
    public static function decode(?string $token, int $leeway = 0): ?stdClass
    {
        $publicKey = PublicKey::getPublicKey(config('keycloak.realm'));

        JWT::$leeway = $leeway;

        return $token ? JWT::decode($token, $publicKey) : null;
    }
}
