<?php

declare(strict_types=1);

namespace KeycloakGuard\Tests\Extensions;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class CustomUserProvider extends EloquentUserProvider
{
    public function custom_retrieve(object $token, array $credentials): ?Authenticatable
    {
        $model = parent::retrieveByCredentials($credentials);
        $model->customRetrieve = true;

        return $model;
    }
}
