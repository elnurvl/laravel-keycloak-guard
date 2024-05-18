<?php

declare(strict_types=1);

namespace KeycloakGuard\Exceptions;

use UnexpectedValueException;

class KeycloakGuardException extends UnexpectedValueException
{
    public function __construct(string $message)
    {
        $this->message = "[Keycloak Guard] $message";

        parent::__construct();
    }
}
