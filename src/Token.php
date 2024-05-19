<?php

declare(strict_types=1);

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use KeycloakGuard\Exceptions\TokenException;
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
        $publicKey = PublicKey::getPublicKey(self::getIss($token));

        JWT::$leeway = $leeway;

        return $token ? JWT::decode($token, $publicKey) : null;
    }

    /**
     * Introspect a JWT token
     *
     * @param string $token
     *
     * @return stdClass|null
     */
    public static function introspect(string $token): ?stdClass
    {
        $iss = self::getIss($token);

        // Try the already-known introspection endpoint first
        try {
            $response = Http::withBasicAuth(config('keycloak.client_id'), config('keycloak.client_secret'))
                ->post($iss.'/protocol/openid-connect/token/introspect', ['token' => $token]);
        } catch (ConnectionException) {
            throw new TokenException("Token does not contain a valid issuer");
        }

        if ($response->successful()) {
            $token = $response->json();

            return $token['active'] ? json_decode($response->body()) : null;
        }

        // Obtain the endpoint from the discovery document if the initially assumed one was not valid
        $wellKnownUrl = $iss.'/.well-known/openid-configuration';
        $wellKnownResponse = Http::get($wellKnownUrl);

        if (!$wellKnownResponse->successful()) {
            throw new TokenException("Unable to fetch well-known configuration.");
        }

        $wellKnownConfig = $wellKnownResponse->json();

        if (!isset($wellKnownConfig['introspection_endpoint'])) {
            throw new TokenException("Introspection endpoint not found in well-known configuration.");
        }

        $introspectionEndpoint = $wellKnownConfig['introspection_endpoint'];
        $response = Http::get($introspectionEndpoint);

        if (!$response->successful()) {
            throw new TokenException("Unable to carry introspection.");
        }

        $token = $response->json();

        return $token['active'] ? json_decode($response->body()) : null;
    }

    private static function getIss(string $token): ?string
    {
        list(, $payload, ) = explode('.', $token);
        $payload = json_decode(base64_decode($payload));

        return $payload->iss;
    }
}
