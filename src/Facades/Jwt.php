<?php

namespace Xaamin\Jwt\Facades;

use Xaamin\Jwt\Jwt as JwtBase;
use Illuminate\Support\Facades\Facade;

class Jwt extends Facade
{
    protected static function getFacadeAccessor()
    {
        return JwtBase::class;
    }
}
